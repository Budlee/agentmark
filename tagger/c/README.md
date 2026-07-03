# `tagger/c` — the C loader

One of two interchangeable loaders for the eBPF program in [`../bpf/`](../bpf). It
uses **libbpf** + a bpftool-generated skeleton. The Go loader in [`../go/`](../go)
does the exact same job; pick either.

## Build

The eBPF program builds separately in [`../bpf`](../bpf); this Makefile just links
the C loader against its skeleton:

```sh
make -C ../bpf   # 1. compile the eBPF program → ../bpf/tagger.skel.h
make             # 2. link the C loader        → ./tagger
```

Or run `make` here alone — it builds `../bpf` on demand. Needs `cc` + libbpf-dev +
libelf + zlib (and `../bpf`'s clang + bpftool). Build **on the target machine** —
CO-RE needs that kernel's BTF.

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
