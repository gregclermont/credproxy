"""Bootstrap routes: workspace-facing endpoints on the merged HTTP API.

Reached from the workspace via the iptables sentinel:80 ->
CREDPROXY_HTTP_PORT redirect installed in entrypoint.sh. All routes
are GET, all unauthenticated -- the data they expose is what the
workspace needs to function (CA cert, env vars, placeholders).
"""
from pathlib import Path

from aiohttp import web

from admin import STATE_KEY
from config import Credentials

CA_CERT_PATH = Path("/home/mitmuser/.mitmproxy/mitmproxy-ca-cert.pem")
VERSION = "0.0.1"

CA_ENV = {
    "SSL_CERT_FILE": "/tmp/proxy-ca.crt",
    "REQUESTS_CA_BUNDLE": "/tmp/proxy-ca.crt",
    "NODE_EXTRA_CA_CERTS": "/tmp/proxy-ca.crt",
    "GIT_SSL_CAINFO": "/tmp/proxy-ca.crt",
    "CARGO_HTTP_CAINFO": "/tmp/proxy-ca.crt",
    "AWS_CA_BUNDLE": "/tmp/proxy-ca.crt",
}

BOOTSTRAP_SH = """#!/bin/sh
# Run via: curl -sSL http://proxy.local/bootstrap.sh | sh
# Run as root (the default in most workspace images).
set -eu
CA_PATH=/tmp/proxy-ca.crt
PROFILE_PATH=/etc/profile.d/credproxy.sh

curl -sf -o "$CA_PATH" http://proxy.local/ca.crt

# System-wide trust covers curl, git, openssl, python stdlib. Best-effort:
# images without ca-certificates installed will skip this gracefully.
if command -v update-ca-certificates >/dev/null 2>&1; then
  cp "$CA_PATH" /usr/local/share/ca-certificates/proxy.crt 2>/dev/null \\
    && update-ca-certificates >/dev/null 2>&1 || true
fi

# Persistent env vars for tools that ignore the system trust store
# (Python requests via certifi, Node, Cargo, AWS SDKs). Picked up by
# future login shells; for the current shell, source it manually.
# Pulled from /env.sh so CA_ENV in the proxy is the single source.
if [ -d /etc/profile.d ] && [ -w /etc/profile.d ]; then
  curl -sf http://proxy.local/env.sh > "$PROFILE_PATH"
fi

echo "Bootstrap complete. CA at $CA_PATH; env in $PROFILE_PATH."
"""

ENV_SH = "".join(f'export {k}="{v}"\n' for k, v in CA_ENV.items())

LLMS_TXT = """\
This sandbox runs behind a transparent egress proxy.

Bootstrap (do this once, as root):

    curl -sSL http://proxy.local/bootstrap.sh | sh

That installs the proxy CA system-wide and writes env vars to
/etc/profile.d/credproxy.sh. HTTPS to configured hosts is intercepted;
everything else is byte-passthrough.

For intercepted hosts, the proxy publishes placeholder tokens under
/setup's `tokens` field. Use those placeholders as you would real
credentials (in env vars, tool config files, request headers); the
proxy substitutes them for real secrets on the way upstream. You will
not see the real values. A request to an intercepted host with no
placeholder is forwarded as-is and logged.

If proxy.local does not resolve, use 169.254.1.1 directly.

Endpoints (all GET):
  /health        liveness probe (json)
  /ca.crt        CA certificate (PEM)
  /bootstrap.sh  one-shot setup: install CA + write /etc/profile.d
  /env.sh        env-var exports only (for `eval` use)
  /setup         JSON: ca_url, env, version, intercept_hosts, tokens
  /llms.txt      this file
"""


def workspace_tokens(creds: Credentials) -> dict[str, dict[str, str]]:
    """JSON shape for /setup's `tokens` field: {host: {header: placeholder}}.

    Derived from the Credentials Protocol's two lookup primitives;
    lives here because the shape is a bootstrap-API contract, not a
    credential-lookup concern.
    """
    return {
        host: {sub.header: sub.placeholder for sub in creds.substitutions_for(host)}
        for host in creds.intercept_hosts()
    }


async def health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "version": VERSION})


async def ca_crt(_: web.Request) -> web.Response:
    try:
        pem = CA_CERT_PATH.read_bytes()
    except FileNotFoundError:
        return web.Response(status=503, text="CA not yet generated\n")
    return web.Response(body=pem, content_type="application/x-pem-file")


async def bootstrap_sh(_: web.Request) -> web.Response:
    return web.Response(body=BOOTSTRAP_SH, content_type="text/x-shellscript")


async def env_sh(_: web.Request) -> web.Response:
    return web.Response(body=ENV_SH, content_type="text/x-shellscript")


async def setup(request: web.Request) -> web.Response:
    state = request.app[STATE_KEY]
    return web.json_response({
        "version": VERSION,
        "ca_url": "http://proxy.local/ca.crt",
        "env": CA_ENV,
        "intercept_hosts": sorted(state.creds.intercept_hosts()),
        "tokens": workspace_tokens(state.creds),
    })


async def llms_txt(_: web.Request) -> web.Response:
    return web.Response(body=LLMS_TXT, content_type="text/plain", charset="utf-8")


bootstrap_routes = [
    web.get("/health", health),
    web.get("/ca.crt", ca_crt),
    web.get("/bootstrap.sh", bootstrap_sh),
    web.get("/env.sh", env_sh),
    web.get("/setup", setup),
    web.get("/llms.txt", llms_txt),
]
