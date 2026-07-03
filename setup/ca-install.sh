#!/usr/bin/env bash
#
# ca-install.sh — generate the mitmproxy CA and trust it VM-wide, so every
# runtime an agent might use accepts the proxy's certificates *without* any
# launch-time action by the user.
#
#   curl / Go / OpenSSL / Python stdlib  → system trust store (/etc/ssl/certs)
#   Python requests/httpx                → certifi bundle
#   Node                                 → NODE_EXTRA_CA_CERTS (via /etc/environment)
#
# Idempotent. Run as root. See the README ("The CA") for why this is unavoidable.
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ca-install.sh must run as root" >&2; exit 1; }

CONFDIR=/etc/agentmark/mitmproxy
CA_PEM="$CONFDIR/mitmproxy-ca-cert.pem"
CA_DST=/usr/local/share/ca-certificates/agentmark-mitmproxy.crt
ENV_FILE=/etc/environment
MITMDUMP="$(command -v mitmdump || true)"

mkdir -p "$CONFDIR"

# 1) Generate the CA if absent. mitmproxy mints its CA into confdir on startup;
#    start it briefly on a throwaway port and let timeout stop it.
if [[ ! -f "$CA_PEM" ]]; then
	echo "[*] Generating mitmproxy CA in $CONFDIR ..."
	[[ -n "$MITMDUMP" ]] || { echo "mitmdump not found; install mitmproxy first" >&2; exit 1; }
	# mitmproxy writes its CA into confdir on startup; SIGKILL (not SIGTERM, which
	# it traps for graceful shutdown and can ignore) guarantees it stops.
	timeout -s KILL 8 "$MITMDUMP" --set confdir="$CONFDIR" --listen-port 18080 -q >/dev/null 2>&1 || true
fi
[[ -f "$CA_PEM" ]] || { echo "CA not generated at $CA_PEM" >&2; exit 1; }
chmod 600 "$CONFDIR"/mitmproxy-ca.pem 2>/dev/null || true   # protect the private key

# 2) System trust store (curl, Go, most OpenSSL programs).
echo "[*] Installing CA into the system trust store ..."
cp "$CA_PEM" "$CA_DST"
update-ca-certificates >/dev/null

# 3) Node is the one runtime that ignores BOTH the system store and certifi, so it
#    needs an explicit pointer. /etc/environment is read by PAM on login → the var
#    is inherited by every child process an agent spawns. curl/Go/Python need no
#    env var (they're covered by steps 2 and 4).
echo "[*] Writing /etc/environment entry (Node) ..."
sed -i '/# >>> agentmark >>>/,/# <<< agentmark <<</d' "$ENV_FILE" 2>/dev/null || true
cat >> "$ENV_FILE" <<EOF
# >>> agentmark >>>
NODE_EXTRA_CA_CERTS=$CA_PEM
# <<< agentmark <<<
EOF

# 4) Best-effort: append to the system Python's certifi bundle (requests/httpx
#    use certifi by default and ignore the system store).
if command -v python3 >/dev/null 2>&1; then
	CERTIFI="$(python3 -c 'import certifi; print(certifi.where())' 2>/dev/null || true)"
	# On Debian/Ubuntu, certifi points at the system bundle — update-ca-certificates
	# already covers it, so don't edit that managed file.
	case "$CERTIFI" in /etc/ssl/*|/usr/share/ca-certificates/*|/etc/pki/*) CERTIFI="";; esac
	if [[ -n "${CERTIFI:-}" && -f "$CERTIFI" ]] && ! grep -qF "agentmark" "$CERTIFI" 2>/dev/null; then
		echo "[*] Appending CA to certifi bundle: $CERTIFI"
		{ echo "# agentmark mitmproxy CA"; cat "$CA_PEM"; } >> "$CERTIFI"
	fi
fi

echo "[+] CA trusted VM-wide. New logins inherit it; existing shells must re-login."
