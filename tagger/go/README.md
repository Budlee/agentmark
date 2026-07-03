# `tagger/go` — the Go loader

One of two interchangeable loaders for the eBPF program in [`../bpf/`](../bpf),
using [cilium/ebpf](https://github.com/cilium/ebpf) — **pure Go, no libbpf and no
CGo at runtime**, so it builds to a single static binary. The C loader in
[`../c/`](../c) does the exact same job; pick either.

Nothing about `../bpf/tagger.bpf.c` changes between loaders — it's still compiled
with `clang -target bpf`. Only the userspace side differs. `bpf2go` is the Go
equivalent of `bpftool gen skeleton`.

## Build

```sh
# 1) generate the shared CO-RE header (same one the C Makefile uses):
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../bpf/vmlinux.h
# 2) compile the BPF program + generate typed bindings, then build:
go generate ./...     # bpf2go: needs clang; emits tagger_bpfel.go / tagger_bpfeb.go
go build -o tagger-go .
```

`bpftool` is still required (for `vmlinux.h`), so this doesn't escape the build
toolchain — it only drops libbpf at *runtime*.

## Run

```sh
sudo ./tagger-go [-agents /etc/agentmark/agents.yaml] [-cgroup /sys/fs/cgroup]
```

Reads the YAML allow-list, attaches the four hooks, and blocks until SIGINT/SIGTERM
(the kernel detaches on exit). It also prints a `[+] agent started` line in real
time whenever a configured agent execs (streamed from the kernel via a ring buffer).

## How it maps to the C loader

| C (`../c/tagger.c`) | Go (`main.go`) |
|---|---|
| `bpftool gen skeleton` → `tagger.skel.h` | `go generate` → `bpf2go` → `tagger_bpfel.go` |
| `tagger_bpf__open_and_load()` | `loadTaggerObjects(&objs, nil)` |
| `skel->maps.agent_paths` / `skel->progs.on_exec` | `objs.AgentPaths` / `objs.OnExec` |
| `parse_agents_file()` (plain text) | `parseAgents()` (YAML via `yaml.v3`) |
| `load_agent_paths()` / `attach_tracepoints()` / `attach_cgroup_connect()` | `loadAgentPaths()` / `attachTracepoints()` / `attachCgroupConnect()` |
| `while (!stop) pause();` | `<-ctx.Done()` (via `signal.NotifyContext`) |
| `goto cleanup; tagger_bpf__destroy()` | `defer objs.Close()` + link `Close()` |

Same shape, native dialect — the only real difference is the cleanup idiom.
