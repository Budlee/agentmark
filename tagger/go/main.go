// SPDX-License-Identifier: MIT
//
// Command tagger is the Go loader for agentmark, using cilium/ebpf (pure Go — no
// libbpf and no CGo at runtime). It is fully interchangeable with the C loader in
// ../c/: both load the SAME eBPF program from ../bpf/, fill the agent_paths
// allow-list, attach the four hooks, and block until interrupted so the programs
// stay attached. Pick whichever loader you prefer.
//
// Its structure mirrors ../c/tagger.c: parse (text) and load (BPF) are separate
// phases, the two attach concerns are separate functions, and run() reads as the
// story while the helpers hold the mechanics.
//
// Build (needs clang + bpftool, same as the C Makefile):
//
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../bpf/vmlinux.h
//	go generate ./...   # bpf2go runs `clang -target bpf` and embeds the object
//	go build            # single static, CGo-free binary
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main tagger ../bpf/tagger.bpf.c -- -I../bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

// maxPathLen must match MAX_PATH_LEN in tagger.h: BPF hash-map keys are compared
// byte-for-byte, so the loader and the kernel must zero-pad the path identically.
const maxPathLen = 256

// agentMark mirrors AGENT_MARK in tagger.h. It's only referenced here for the
// startup log line; the mark itself is stamped inside the BPF program.
const agentMark = 0xA1

// pathKey mirrors `struct path_key { char path[256]; }`. A zero-valued array
// gives the same zero-padding tagger.c does with `struct path_key key = {0}`.
type pathKey [maxPathLen]byte

// agentsFile is the YAML schema for the allow-list: a list of invoked paths.
//
//	agents:
//	  - /usr/local/bin/claude
type agentsFile struct {
	Agents []string `yaml:"agents"`
}

// startEvent mirrors `struct event { __u32 pid; char path[256]; }` in tagger.h —
// streamed from the exec hook via a ring buffer when a configured agent starts.
type startEvent struct {
	Pid  uint32
	Path [maxPathLen]byte
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run reads as the story; each step delegates to a named helper. Its defers do
// the teardown — main funnels through here so log.Fatal's os.Exit can't skip them.
func run() error {
	agentsPath := flag.String("agents", "/etc/agentmark/agents.yaml", "path to the agents allow-list (YAML)")
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "unified cgroup v2 root for the connect hooks")
	flag.Parse()

	// eBPF objects are charged against RLIMIT_MEMLOCK on kernels older than 5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// Load the BPF programs and maps into the kernel.
	var objs taggerObjects
	if err := loadTaggerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objs.Close()

	// Parse the allow-list and load it — BEFORE attaching, so no agent can exec
	// in the gap between "hooks live" and "map populated".
	paths, err := parseAgents(*agentsPath)
	if err != nil {
		return fmt.Errorf("parse agents: %w", err)
	}
	n := loadAgentPaths(objs.AgentPaths, paths)

	// Attach the hooks: identity tracking first, then socket marking.
	tracepoints, err := attachTracepoints(&objs)
	if err != nil {
		return err
	}
	defer tracepoints.Close()

	connects, err := attachCgroupConnect(&objs, *cgroupPath)
	if err != nil {
		return err
	}
	defer connects.Close()

	// Stream agent-start events from the exec hook and log them live.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()
	go streamEvents(rd)

	log.Printf("agent-tagger running: %d agent paths, mark=%#x", n, agentMark)

	// Run until interrupted; the deferred Close() calls detach on the way out.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("signal received, detaching")
	return nil
}

// streamEvents reads agent-start events from the ring buffer and logs each one,
// until the reader is closed on shutdown. The Go twin of the C loader's
// ring_buffer__poll loop + handle_event.
func streamEvents(rd *ringbuf.Reader) {
	var e startEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parse event: %v", err)
			continue
		}
		path := string(bytes.TrimRight(e.Path[:], "\x00"))
		log.Printf("[+] agent started: pid=%d  %s", e.Pid, path)
	}
}

// parseAgents reads the YAML allow-list and returns the configured paths.
// Pure parsing, no BPF — the Go twin of parse_agents_file() in tagger.c. YAML
// must never be hand-parsed, so this uses gopkg.in/yaml.v3.
func parseAgents(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg agentsFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg.Agents, nil
}

// loadAgentPaths inserts each path into agent_paths as a zero-padded key
// (matching the kernel byte-for-byte). Pure BPF, no parsing — the Go twin of
// load_agent_paths() in tagger.c. Returns the number of paths loaded.
func loadAgentPaths(m *ebpf.Map, paths []string) int {
	n := 0
	for _, p := range paths {
		if p == "" {
			continue
		}
		if len(p) >= maxPathLen {
			log.Printf("skipping path longer than %d bytes: %s", maxPathLen-1, p)
			continue
		}

		var key pathKey
		copy(key[:], p) // trailing bytes stay zero → byte-for-byte kernel match

		// The value is a dummy: agent_paths is used as a *set*, so presence is
		// the only signal. A per-entry failure (e.g. the map's 64-entry limit)
		// is logged and skipped rather than aborting the whole tagger.
		if err := m.Update(&key, uint8(1), ebpf.UpdateAny); err != nil {
			log.Printf("insert %q: %v", p, err)
			continue
		}
		n++
	}
	return n
}

// attachTracepoints attaches the exec/fork/exit tp_btf programs. Their target is
// carried in each program's SEC() name, so no target string is needed here —
// the Go twin of attach_tracepoints() in tagger.c.
func attachTracepoints(objs *taggerObjects) (links, error) {
	var ls links
	for _, tp := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched_process_exec", objs.OnExec},
		{"sched_process_fork", objs.OnFork},
		{"sched_process_exit", objs.OnExit},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: tp.prog})
		if err != nil {
			ls.Close() // roll back the ones already attached
			return nil, fmt.Errorf("attach %s: %w", tp.name, err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// attachCgroupConnect attaches the connect4/6 programs to the unified cgroup
// root, which covers every process on the host; selection happens inside the
// program via tagged_pids — the Go twin of attach_cgroup_connect() in tagger.c.
func attachCgroupConnect(objs *taggerObjects, cgroupPath string) (links, error) {
	var ls links
	for _, c := range []struct {
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, objs.CgConnect4},
		{ebpf.AttachCGroupInet6Connect, objs.CgConnect6},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  c.attach,
			Program: c.prog,
		})
		if err != nil {
			ls.Close() // roll back the ones already attached
			return nil, fmt.Errorf("attach cgroup connect: %w", err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// links is a set of attached BPF links that detach together. The kernel also
// detaches everything when the process exits; Close makes shutdown explicit.
type links []link.Link

func (ls links) Close() error {
	var errs []error
	for _, l := range ls {
		errs = append(errs, l.Close())
	}
	return errors.Join(errs...)
}
