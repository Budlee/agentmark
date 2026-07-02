#!/usr/bin/env bash
#
# setup.sh — one-command wiring for agentmark on a Linux VM. Idempotent. Run as root.
#
# It builds the C tagger, installs the config + mitmproxy addon, trusts the MITM
# CA VM-wide, and enables the redirect (sysctls + nftables). It does NOT daemonize
# — it prints the two commands to run the system, so nothing is hidden. The README
# walks each step individually.
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "setup.sh must run as root" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # setup/
ROOT="$(dirname "$HERE")"                              # the agentmark/ checkout
ETC=/etc/agentmark

echo "== agentmark setup =="

# 0) Required tools (install on Debian/Ubuntu if missing). bpftool has no standalone
#    package on Ubuntu 24.04 — it ships in linux-tools-generic; symlink it onto PATH.
if command -v apt-get >/dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y
	apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev make \
		nftables mitmproxy ca-certificates python3 curl iproute2 || true
	command -v bpftool >/dev/null 2>&1 || apt-get install -y linux-tools-generic || true
	command -v bpftool >/dev/null 2>&1 \
		|| ln -sf "$(find /usr/lib/linux-tools* -name bpftool | head -1)" /usr/local/bin/bpftool
fi
for t in clang bpftool nft mitmdump; do
	command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; exit 1; }
done

# 1) Build + install the eBPF tagger (C loader). Prefer the Go loader? Build
#    tagger/go instead and install its binary here — the two are interchangeable.
echo "[*] Building the tagger ..."
make -C "$ROOT/tagger/c"
install -D -m 0755 "$ROOT/tagger/c/tagger" /usr/local/sbin/agentmark-tagger

# 2) Config + mitmproxy addon. Install BOTH allow-lists so either loader works out
#    of the box (C reads agents.conf, Go reads agents.yaml).
install -D -m 0644 "$ROOT/config/agents.conf"   "$ETC/agents.conf"
install -D -m 0644 "$ROOT/config/agents.yaml"   "$ETC/agents.yaml"
install -D -m 0644 "$ROOT/mitm/inject_addon.py" "$ETC/inject_addon.py"

# 3) Trust the MITM CA VM-wide (curl/Go via system store; Node/Python via /etc/environment).
bash "$ROOT/setup/ca-install.sh"

# 4) sysctls: a REDIRECT to 127.0.0.1 needs route_localnet=1 or the kernel drops it.
install -m 0644 "$ROOT/setup/90-redirect.conf" /etc/sysctl.d/90-agentmark.conf
sysctl --system >/dev/null

# 5) nftables: load the redirect now, and persist it across reboot via an include.
install -m 0644 "$ROOT/setup/redirect.nft" "$ETC/redirect.nft"
nft -f "$ETC/redirect.nft"
if [[ ! -f /etc/nftables.conf ]]; then
	printf '#!/usr/sbin/nft -f\nflush ruleset\n' > /etc/nftables.conf
fi
grep -q 'agentmark/redirect.nft' /etc/nftables.conf \
	|| echo "include \"$ETC/redirect.nft\"" >> /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1 || true

cat <<EOF

[+] agentmark is wired up. It runs as two foreground processes (no services):

    # 1. the proxy — terminates TLS and injects the header; leave it running:
    sudo mitmdump --mode transparent --showhost \\
      --set confdir=$ETC/mitmproxy -s $ETC/inject_addon.py --listen-port 8080
    #    (use interactive 'mitmproxy' instead of 'mitmdump' to watch flows live)

    # 2. the tagger — marks agent sockets; run in another terminal:
    sudo /usr/local/sbin/agentmark-tagger $ETC/agents.conf /sys/fs/cgroup

    Agents:    edit $ETC/agents.conf (one invoked path per line)
    Roll back: sudo $ROOT/setup/teardown.sh
EOF
