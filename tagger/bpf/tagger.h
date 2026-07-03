/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/* tagger.h — shared definitions between the BPF program and the userspace loader.
 *
 * Keeping the map-key layout in one place guarantees the kernel side and the
 * userspace side agree on the exact bytes: a BPF hash map compares keys
 * byte-for-byte, so both sides must zero-pad identically.
 */
#ifndef __TAGGER_H
#define __TAGGER_H

/* The fwmark we stamp on a tagged process's sockets. nftables matches this
 * (`meta mark 0xA1`) to decide what to REDIRECT to mitmproxy. Any non-zero
 * value works as long as redirect.nft agrees. */
#define AGENT_MARK 0xA1

/* Max length of an agent binary path we match against. */
#define MAX_PATH_LEN 256

/* Max number of agent paths — also the agent_paths BPF map capacity, so the
 * userspace parse buffer and the kernel map can't disagree on the limit. */
#define MAX_AGENTS 64

/*
 * We match agent binaries by the path passed to execve() — i.e. the kernel's
 * `bprm->filename`. This is deliberately the *invoked path*, not the inode:
 *
 *   - It correctly identifies interpreted CLIs. `claude`/`codex` are typically
 *     `#!/usr/bin/env node` scripts; the kernel ends up executing `node`, but
 *     `bprm->filename` stays "/usr/local/bin/claude". Matching the inode would
 *     instead see `node` and tag *every* Node process.
 *   - It survives reinstalls/upgrades (the path is stable; the inode is not).
 *
 * agents.conf therefore lists the paths users actually invoke (what
 * `command -v claude` prints). The key is zero-padded to MAX_PATH_LEN on both
 * sides so the byte-for-byte hash-map comparison matches.
 */
struct path_key {
	char path[MAX_PATH_LEN];
};

/* Streamed from the exec hook to the loader via a ring buffer when a configured
 * agent starts, so the loader can log the start in real time. */
struct event {
	__u32 pid;
	char  path[MAX_PATH_LEN];
};

#endif /* __TAGGER_H */
