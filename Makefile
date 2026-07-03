# Root convenience Makefile. The eBPF program (tagger/bpf) and the C loader
# (tagger/c) build separately; the Go loader (tagger/go) uses bpf2go. See the
# per-directory Makefiles and READMEs.

.PHONY: all bpf c go clean

all: c   ## build the C loader (compiles the eBPF program first)

bpf:     ## build just the eBPF program -> tagger/bpf/tagger.skel.h
	$(MAKE) -C tagger/bpf

c: bpf   ## build the C loader -> tagger/c/tagger
	$(MAKE) -C tagger/c

go:      ## build the Go loader -> tagger/go/tagger-go
	$(MAKE) -C tagger/bpf vmlinux.h
	cd tagger/go && go generate ./... && go build -o tagger-go .

clean:   ## remove all build artifacts (bpf + c + go)
	$(MAKE) -C tagger/bpf clean
	$(MAKE) -C tagger/c clean
	rm -f tagger/go/tagger-go tagger/go/tagger_bpfel.go tagger/go/tagger_bpfeb.go tagger/go/*.o
