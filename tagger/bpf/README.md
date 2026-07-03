# `tagger/bpf` — the eBPF program

The kernel-side program (`tagger.bpf.c`) and its shared key/constant header
(`tagger.h`), plus a Makefile that compiles them into a **loader-ready skeleton**.
This is the one program both loaders run:

- the **C loader** (`../c`) `#include`s the generated `tagger.skel.h`;
- the **Go loader** (`../go`) regenerates its own bindings from `tagger.bpf.c` via `bpf2go`.

## Build

```sh
make        # -> tagger.skel.h   (+ tagger.bpf.o, vmlinux.h)
```

The CO-RE pipeline, each step visible:

1. `bpftool btf dump` → `vmlinux.h` — kernel struct layouts from the **running
   kernel's BTF** (why you build on the target machine).
2. `clang -target bpf` → `tagger.bpf.o` — the program compiled to BPF bytecode.
3. `bpftool gen skeleton` → `tagger.skel.h` — bytecode + typed handles the loader embeds.

Deps: `clang`, `bpftool`. Then build the loader in [`../c`](../c) (or [`../go`](../go)).
