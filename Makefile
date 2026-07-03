# Root convenience Makefile. The real builds live in tagger/c (make) and
# tagger/go (go generate + go build); both compile the shared eBPF program in
# tagger/bpf. See README.md and the per-loader READMEs.

.PHONY: all c go clean

all: c   ## build the C loader (default)

c:       ## build the C loader -> tagger/c/tagger
	$(MAKE) -C tagger/c

go:      ## build the Go loader -> tagger/go/tagger-go
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > tagger/bpf/vmlinux.h
	cd tagger/go && go generate ./... && go build -o tagger-go .

clean:   ## remove build artifacts from both loaders
	$(MAKE) -C tagger/c clean
	rm -f tagger/go/tagger-go tagger/go/tagger_bpfel.go tagger/go/tagger_bpfeb.go tagger/go/*.o
