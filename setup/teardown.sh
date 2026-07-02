#!/usr/bin/env bash
#
# teardown.sh — remove the agentmark header-injection setup and return the VM to
# a clean state. Idempotent and safe to run repeatedly. Run as root.
#
# Undoes everything setup.sh / ca-install.sh set up:
#   - stops the tagger + mitmproxy processes (detaching the eBPF)
#   - deletes the nftables table (and the persistent include)
#   - removes the sysctl drop-in (and resets the live value)
#   - removes the MITM CA from the system trust store
#   - strips the agentmark block from /etc/environment
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "teardown.sh must run as root" >&2
	exit 1
fi

CA_NAME="agentmark-mitmproxy"
CA_CRT="/usr/local/share/ca-certificates/${CA_NAME}.crt"
ENV_FILE="/etc/environment"
NFT_TABLE="inet agentmark"
SYSCTL_DROPIN="/etc/sysctl.d/90-agentmark.conf"

echo "[*] Stopping the tagger and mitmproxy..."
pkill -f agentmark-tagger 2>/dev/null || true
pkill -f mitmdump         2>/dev/null || true
pkill -f 'mitmproxy '     2>/dev/null || true

echo "[*] Deleting nftables table ($NFT_TABLE)..."
nft delete table $NFT_TABLE 2>/dev/null || true
if [[ -f /etc/nftables.conf ]]; then
	# Remove the persistent include line (delimiter '#' so the path's / are literal).
	sed -i '\#include "/etc/agentmark/redirect.nft"#d' /etc/nftables.conf 2>/dev/null || true
fi

echo "[*] Removing sysctl drop-in..."
rm -f "$SYSCTL_DROPIN"
sysctl -q -w net.ipv4.conf.all.route_localnet=0 2>/dev/null || true

echo "[*] Removing MITM CA from the system trust store..."
rm -f "$CA_CRT"
update-ca-certificates --fresh >/dev/null 2>&1 \
	|| update-ca-certificates >/dev/null 2>&1 || true

echo "[*] Stripping agentmark block from $ENV_FILE..."
# Markers are literal text (no regex-special chars), so this range delete is safe.
sed -i '/# >>> agentmark >>>/,/# <<< agentmark <<</d' "$ENV_FILE" 2>/dev/null || true

cat <<'EOF'
[+] Teardown complete.
    New logins and processes are no longer intercepted.
    Note: if ca-install.sh appended the CA to a Python `certifi` bundle, that
    append is left in place — reinstall certifi (`pip install --force-reinstall
    certifi`) if you want a pristine Python trust store.
EOF
