"""
inject_addon.py — mitmproxy addon that stamps `X-AI-Agent: TRUE` onto the
HTTP(S) requests it proxies.

This is the *only* place the header is actually added. Everything else in the
project exists to make sure the right traffic arrives here, decrypted:

    eBPF tags the sockets of an agent's SUBPROCESSES → nftables REDIRECTs them
    here → mitmproxy terminates TLS (with a trusted CA) → THIS addon adds the
    header → mitmproxy re-encrypts and forwards to the real server.

The agent process itself is left unmarked; only the tool processes it spawns are
redirected. So every request seen here already belongs to a subprocess of a
configured agent, and by default we inject unconditionally.

Optional scoping: set AGENT_INJECT_HOSTS to a comma-separated host list to inject
only for those destinations (everything else is still proxied, just not stamped).
Example:  AGENT_INJECT_HOSTS="api.anthropic.com,api.openai.com"

Load it with:  mitmproxy/mitmdump -s inject_addon.py
"""
import os

HEADER_NAME = "X-AI-Agent"
HEADER_VALUE = "TRUE"

# Empty set => inject for all hosts.
_hosts_env = os.environ.get("AGENT_INJECT_HOSTS", "").strip()
TARGET_HOSTS = {h.strip().lower() for h in _hosts_env.split(",") if h.strip()}


def request(flow):
    """Called by mitmproxy for every request, before it's sent upstream."""
    if TARGET_HOSTS and flow.request.pretty_host.lower() not in TARGET_HOSTS:
        return
    # Overwrite rather than add, so a client can't smuggle a conflicting value.
    flow.request.headers[HEADER_NAME] = HEADER_VALUE
