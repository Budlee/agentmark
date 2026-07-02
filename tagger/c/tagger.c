// SPDX-License-Identifier: MIT
/*
 * tagger.c — the C userspace loader for tagger.bpf.c (libbpf / CO-RE).
 *
 * One of two interchangeable loaders (the other is ../go/main.go); both load the
 * same eBPF program from ../bpf/. Responsibilities:
 *   1. Load the BPF object and create its maps.
 *   2. Read agents.conf and insert each configured binary path (zero-padded)
 *      into the agent_paths map — this is the allow-list.
 *   3. Attach the tracepoint programs (exec/fork/exit) and the cgroup connect
 *      programs (to the unified cgroup root so they see every process).
 *   4. Stay running so the programs remain attached; on exit (or signal) the
 *      kernel detaches everything.
 *
 * Usage: tagger [agents.conf] [cgroup-root]
 *   defaults: /etc/agentmark/agents.conf  /sys/fs/cgroup
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tagger.h"
#include "tagger.skel.h"

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/*
 * Parse one raw line from agents.conf into a clean path, trimmed in place.
 * Returns a pointer to the path, or NULL if the line is a comment, blank, or
 * all-whitespace (nothing to add). Pure text handling — no BPF here.
 */
static char *parse_agent_line(char *line)
{
	char *p = line;

	while (*p == ' ' || *p == '\t')            /* skip leading whitespace */
		p++;
	if (*p == '#' || *p == '\n' || *p == '\0') /* comment / blank line */
		return NULL;

	size_t len = strlen(p);                    /* trim trailing whitespace */
	while (len && (p[len - 1] == '\n' || p[len - 1] == '\r' ||
		       p[len - 1] == ' '  || p[len - 1] == '\t'))
		p[--len] = '\0';

	return len ? p : NULL;
}

/*
 * A parsed allow-list: the agent paths extracted from the file, bounded by the
 * agent_paths map's capacity (MAX_AGENTS, shared via tagger.h).
 */
struct agent_list {
	char   paths[MAX_AGENTS][MAX_PATH_LEN];
	size_t count;
};

/*
 * PHASE 1 — parse the whole file into a list of clean agent paths.
 * Pure text + memory: clean each line with parse_agent_line and collect the
 * survivors. No BPF here. Returns 0 on success (count in out->count), or -1 if
 * the file can't be opened.
 */
static int parse_agents_file(const char *path, struct agent_list *out)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}

	out->count = 0;
	char line[MAX_PATH_LEN + 64];
	while (fgets(line, sizeof(line), f)) {
		char *agent = parse_agent_line(line);
		if (!agent)
			continue;

		size_t len = strlen(agent);
		if (len >= MAX_PATH_LEN) {
			fprintf(stderr, "path too long (>%d), skipped: %s\n", MAX_PATH_LEN - 1, agent);
			continue;
		}
		if (out->count == MAX_AGENTS) {
			fprintf(stderr, "too many agents (>%d), ignoring the rest\n", MAX_AGENTS);
			break;
		}

		memcpy(out->paths[out->count++], agent, len + 1);  /* copy incl. NUL */
	}

	fclose(f);
	return 0;
}

/*
 * PHASE 2 — load a parsed list of paths into the agent_paths map.
 * Pure BPF: build a zero-padded key per path (matching the kernel byte-for-byte)
 * and insert it. No parsing here. Returns the number of paths loaded.
 */
static int load_agent_paths(int map_fd, const struct agent_list *agents)
{
	int n = 0;

	for (size_t i = 0; i < agents->count; i++) {
		const char *path = agents->paths[i];

		struct path_key key = {0};
		memcpy(key.path, path, strlen(path));

		__u8 val = 1;   /* value unused: agent_paths is a set, presence is the signal */
		if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
			fprintf(stderr, "map update for %s: %s\n", path, strerror(errno));
			continue;
		}
		printf("  + agent path: %s\n", path);
		n++;
	}

	return n;
}

/*
 * Attach the process-tracking tracepoints (exec/fork/exit). Their attach target
 * is encoded in each program's SEC() name, so bpf_program__attach resolves it.
 * The links are stored in the skeleton, so tagger_bpf__destroy() frees them.
 */
static int attach_tracepoints(struct tagger_bpf *skel)
{
	skel->links.on_exec = bpf_program__attach(skel->progs.on_exec);
	skel->links.on_fork = bpf_program__attach(skel->progs.on_fork);
	skel->links.on_exit = bpf_program__attach(skel->progs.on_exit);

	if (!skel->links.on_exec || !skel->links.on_fork || !skel->links.on_exit) {
		fprintf(stderr, "attach tracepoints failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Attach the socket-marking cgroup/connect hooks (IPv4 + IPv6). Unlike
 * tracepoints these need a cgroup to attach to; the unified root covers every
 * process on the host. The cgroup fd is only needed during attach — the links
 * (stored in the skeleton for cleanup) hold the attachment afterwards.
 */
static int attach_cgroup_connect(struct tagger_bpf *skel, const char *cgroup_path)
{
	int cg = open(cgroup_path, O_RDONLY);
	if (cg < 0) {
		fprintf(stderr, "open cgroup %s: %s\n", cgroup_path, strerror(errno));
		return -1;
	}

	skel->links.cg_connect4 = bpf_program__attach_cgroup(skel->progs.cg_connect4, cg);
	skel->links.cg_connect6 = bpf_program__attach_cgroup(skel->progs.cg_connect6, cg);
	close(cg);

	if (!skel->links.cg_connect4 || !skel->links.cg_connect6) {
		fprintf(stderr, "attach cgroup connect failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *agents_path = argc > 1 ? argv[1] : "/etc/agentmark/agents.conf";
	const char *cgroup_path = argc > 2 ? argv[2] : "/sys/fs/cgroup";
	struct agent_list agents;
	int n = 0, rc = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);  /* line-buffered: logs appear promptly under systemd */
	libbpf_set_print(libbpf_print);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Load the BPF programs and maps into the kernel. */
	struct tagger_bpf *skel = tagger_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}

	/* Parse the allow-list and load it into the map — BEFORE attaching, so no
	 * agent can exec in the gap between "hooks live" and "map populated". */
	if (parse_agents_file(agents_path, &agents) < 0)
		goto cleanup;
	n = load_agent_paths(bpf_map__fd(skel->maps.agent_paths), &agents);

	/* Attach the hooks: identity tracking first, then socket marking. */
	if (attach_tracepoints(skel) < 0)
		goto cleanup;
	if (attach_cgroup_connect(skel, cgroup_path) < 0)
		goto cleanup;

	/* Run until signalled; the kernel detaches everything when we exit. */
	printf("agent-tagger running: %d agent paths, mark=0x%x. Signal to stop.\n",
	       n, AGENT_MARK);
	while (!stop)
		pause();

	rc = 0;

cleanup:
	tagger_bpf__destroy(skel);
	return rc;
}
