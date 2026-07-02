# Makefile — build the C agentmark tagger (libbpf / CO-RE).
#
# The eBPF program is shared and lives in ../bpf/ (tagger.bpf.c, tagger.h); this
# builds the C loader (tagger.c) against it. The Go loader in ../go/ consumes the
# same ../bpf/ program via bpf2go — pick whichever loader you prefer.
#
# Build dependencies (Debian/Ubuntu): clang llvm libbpf-dev libelf-dev zlib1g-dev
#   bpftool  (from linux-tools-generic / linux-tools-$(uname -r))
# Runtime: kernel with BTF at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y).

CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc

BPF_DIR  := ../bpf

# Map `uname -m` to the arch token bpf_tracing.h expects.
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/mips.*/mips/')

# Locate libbpf headers/libs via pkg-config, with a sane fallback.
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null || echo -lbpf)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS)

.PHONY: all clean
all: tagger

# CO-RE kernel type definitions, generated from the running kernel's BTF, into
# ../bpf/ so both this Makefile and the Go bpf2go build find it next to the source.
$(BPF_DIR)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

tagger.bpf.o: $(BPF_DIR)/tagger.bpf.c $(BPF_DIR)/tagger.h $(BPF_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_DIR) -c $< -o $@

# Skeleton: embeds the BPF object + typed accessors for the loader.
tagger.skel.h: tagger.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

tagger: tagger.c tagger.skel.h $(BPF_DIR)/tagger.h
	$(CC) -g -O2 -Wall -I. -I$(BPF_DIR) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f tagger tagger.bpf.o tagger.skel.h $(BPF_DIR)/vmlinux.h
