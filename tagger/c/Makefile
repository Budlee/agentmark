# Makefile — build the C loader (libbpf) against the eBPF skeleton from ../bpf.
#
# The eBPF program builds separately in ../bpf. Demo them apart:
#     make -C ../bpf      # 1. compile the eBPF program -> ../bpf/tagger.skel.h
#     make                # 2. link the C loader        -> ./tagger
# Running `make` here alone also works — it builds ../bpf on demand.
#
# Deps: cc, libbpf-dev, libelf, zlib (+ ../bpf's clang/bpftool).

CC      ?= cc
BPF_DIR := ../bpf

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null || echo -lbpf)

.PHONY: all clean
all: tagger

# The skeleton is an artifact of the eBPF build in ../bpf. Delegate to that
# Makefile so it's built (or rebuilt when the BPF sources change).
$(BPF_DIR)/tagger.skel.h: $(BPF_DIR)/tagger.bpf.c $(BPF_DIR)/tagger.h
	$(MAKE) -C $(BPF_DIR)

tagger: tagger.c $(BPF_DIR)/tagger.skel.h $(BPF_DIR)/tagger.h
	$(CC) -g -O2 -Wall -I. -I$(BPF_DIR) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f tagger
