# Makefile — build the eBPF program (CO-RE) into a loader-ready skeleton.
#
# Produces tagger.skel.h (+ tagger.bpf.o, vmlinux.h) here in tagger/bpf/. Both
# loaders consume this program: the C loader (../c) #includes tagger.skel.h; the
# Go loader (../go) regenerates its own bindings from tagger.bpf.c via bpf2go.
#
# Deps: clang, bpftool. Build ON THE TARGET machine — CO-RE needs that kernel's BTF.

CLANG   ?= clang
BPFTOOL ?= bpftool

# Map `uname -m` to the arch token bpf_tracing.h expects.
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/mips.*/mips/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS)

.PHONY: all clean
all: tagger.skel.h

# CO-RE kernel type definitions, generated from the running kernel's BTF.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile the BPF program to BPF bytecode.
tagger.bpf.o: tagger.bpf.c tagger.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

# Wrap the object in a skeleton the userspace loader embeds and drives.
tagger.skel.h: tagger.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f tagger.bpf.o tagger.skel.h vmlinux.h
