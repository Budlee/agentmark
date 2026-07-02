# `tagger/c` — the C loader

One of two interchangeable loaders for the eBPF program in [`../bpf/`](../bpf). It
uses **libbpf** + a bpftool-generated skeleton. The Go loader in [`../go/`](../go)
does the exact same job; pick either.

## Build

```sh
make          # → ./tagger   (needs clang, bpftool, libbpf-dev, libelf, zlib)
```

`make` runs the CO-RE pipeline: `bpftool btf dump` generates `../bpf/vmlinux.h`,
`clang -target bpf` compiles `../bpf/tagger.bpf.c`, `bpftool gen skeleton` wraps it,
and `cc` links the loader against libbpf. Build **on the target machine** — CO-RE
needs that kernel's BTF.

## Run

```sh
# needs CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN (root is simplest)
sudo ./tagger [agents.conf] [cgroup-root]
#   defaults: /etc/agentmark/agents.conf  /sys/fs/cgroup
```

It reads the allow-list, attaches the exec/fork/exit tracepoints and the
cgroup/connect hooks, then runs until signalled (the kernel detaches everything on
exit). While running: `sudo bpftool map dump name tagged_pids` shows the live set.

## Structure

`main()` reads as the story — load → parse allow-list → load into the map → attach
identity hooks → attach marking hooks → run — with each step in a named helper
(`parse_agents_file`, `load_agent_paths`, `attach_tracepoints`,
`attach_cgroup_connect`). Config format: plain text (one path per line, `#`
comments). See [`../go/`](../go) for the same shape in Go with a YAML config.
