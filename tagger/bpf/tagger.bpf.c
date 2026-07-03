// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * tagger.bpf.c — the kernel-side eBPF program. It answers one question:
 *   "Is the process making this network connection a configured coding agent,
 *    or a descendant of one?"
 * and if so, stamps a fwmark on the socket so nftables can REDIRECT it.
 *
 * Four hooks + two maps implement the "identity" half of the system:
 *
 *   sched_process_exec  ──▶ if the exec'd path is in the agent allow-list,
 *                           record this PID as tagged.
 *   sched_process_fork  ──▶ if the parent is tagged, tag the child too
 *                           (this is how the *whole subprocess tree* is caught).
 *   sched_process_exit  ──▶ forget the PID (so recycled PIDs aren't mis-tagged).
 *   cgroup/connect4|6   ──▶ when a tagged PID connects out, set SO_MARK.
 *
 * Everything is CO-RE (Compile Once – Run Everywhere): we read kernel structs
 * through BPF_CORE_READ so the same object loads across kernel versions.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tagger.h"

/* Must be GPL-compatible: the tracing/CO-RE helpers we use (bpf_probe_read_kernel*)
 * are GPL-only, and the kernel rejects a plain "MIT" string. "Dual MIT/GPL" keeps
 * the code MIT-licensed while satisfying the kernel's compatibility check. */
char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Constants not present in vmlinux.h. */
#define SOL_SOCKET 1
#define SO_MARK    36

/* The agent allow-list, keyed by invoked path. Populated from agents.conf by
 * the userspace loader. Value is unused (presence == "this is an agent"). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_AGENTS);
	__type(key, struct path_key);
	__type(value, __u8);
} agent_paths SEC(".maps");

/* The live set of tagged PIDs (agents + their descendants), keyed by tgid. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} tagged_pids SEC(".maps");

/* Ring buffer: the exec hook streams an event here when a configured agent
 * starts, so the userspace loader can log it live. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);   /* 256 KiB */
} events SEC(".maps");

static __always_inline void tag_tgid(__u32 tgid)
{
	__u8 one = 1;
	bpf_map_update_elem(&tagged_pids, &tgid, &one, BPF_ANY);
}

/*
 * EXEC: a process just successfully exec'd a new program. We read the invoked
 * path (bprm->filename) and tag the process if it's an agent. Fires *before*
 * the new program runs, so the tag is in place before the agent makes any call.
 *
 * We only ever ADD here. A Node-based agent re-execs (claude → env → node) keep
 * the same PID; the first exec (filename = the agent path) tags it, and the
 * later `node` exec doesn't match but never untags. Likewise a descendant that
 * was tagged via fork and then execs `curl` stays tagged.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct path_key key = {};
	const char *filename = BPF_CORE_READ(bprm, filename);

	/* key.path is zero-initialised above; read_str fills the prefix + NUL,
	 * leaving the tail zeroed to match the loader's zero-padded keys. */
	bpf_probe_read_kernel_str(key.path, sizeof(key.path), filename);

	if (bpf_map_lookup_elem(&agent_paths, &key)) {
		__u32 tgid = BPF_CORE_READ(p, tgid);
		tag_tgid(tgid);

		/* Tell the loader an agent just started. */
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->pid = tgid;
			__builtin_memcpy(e->path, key.path, sizeof(e->path));
			bpf_ringbuf_submit(e, 0);
		}
	}

	return 0;
}

/*
 * FORK: propagate the tag down the process tree. If the parent is an agent (or
 * a tagged descendant), the child inherits the tag. Fires before the child runs.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ptgid = BPF_CORE_READ(parent, tgid);

	if (bpf_map_lookup_elem(&tagged_pids, &ptgid))
		tag_tgid(BPF_CORE_READ(child, tgid));

	return 0;
}

/*
 * EXIT: clean up so a future process that reuses this PID isn't accidentally
 * treated as an agent. sched_process_exit fires per-thread; only act when the
 * thread-group leader exits (pid == tgid), i.e. the whole process is gone.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	__u32 pid  = BPF_CORE_READ(p, pid);
	__u32 tgid = BPF_CORE_READ(p, tgid);

	if (pid == tgid)
		bpf_map_delete_elem(&tagged_pids, &tgid);

	return 0;
}

/*
 * CONNECT (IPv4): runs in the context of the process calling connect(). If that
 * process is tagged, stamp AGENT_MARK on the socket via SO_MARK. The mark is
 * copied to every outgoing skb, where nftables matches it. Returning 1 allows
 * the connection (0 would block it). bpf_setsockopt() is permitted in the
 * INET4/INET6_CONNECT cgroup hooks on modern kernels (>= 5.8).
 */
SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (bpf_map_lookup_elem(&tagged_pids, &tgid)) {
		__u32 mark = AGENT_MARK;
		bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	}
	return 1;
}

/* CONNECT (IPv6): identical logic for AF_INET6. */
SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (bpf_map_lookup_elem(&tagged_pids, &tgid)) {
		__u32 mark = AGENT_MARK;
		bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	}
	return 1;
}
