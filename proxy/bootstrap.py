"""Bootstrap HTTP API.

Served on 127.0.0.1:39998. iptables redirects sentinel-IP:80 here so the
agent can `curl http://proxy.local/<endpoint>`. Plain HTTP is fine: the
shared netns has no eavesdropper.
"""
from pathlib import Path

from aiohttp import web

from config import Credentials

CA_CERT_PATH = Path("/home/mitmuser/.mitmproxy/mitmproxy-ca-cert.pem")
VERSION = "0.0.1"
CREDS_KEY = web.AppKey("creds", Credentials)

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
if [ -d /etc/profile.d ] && [ -w /etc/profile.d ]; then
  cat > "$PROFILE_PATH" <<EOF
export SSL_CERT_FILE="$CA_PATH"
export REQUESTS_CA_BUNDLE="$CA_PATH"
export NODE_EXTRA_CA_CERTS="$CA_PATH"
export GIT_SSL_CAINFO="$CA_PATH"
export CARGO_HTTP_CAINFO="$CA_PATH"
export AWS_CA_BUNDLE="$CA_PATH"
EOF
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

For intercepted hosts, the proxy publishes placeholder tokens via
/tokens. Use those placeholders as you would real credentials (in env
vars, tool config files, request headers); the proxy substitutes them
for real secrets on the way upstream. You will not see the real values.
A request to an intercepted host with no placeholder is forwarded as-is
and logged.

If proxy.local does not resolve, use 169.254.1.1 directly.

Endpoints (all GET):
  /health        liveness probe (json)
  /ca.crt        CA certificate (PEM)
  /bootstrap.sh  one-shot setup: install CA + write /etc/profile.d
  /env.sh        env-var exports only (for `eval` use)
  /setup         JSON: ca_url, env, version
  /domains       JSON: configured intercept hosts
  /tokens        JSON: {host: {header: placeholder}} per-host placeholders
  /llms.txt      this file
"""


def _no_store(resp: web.StreamResponse) -> web.StreamResponse:
    resp.headers["Cache-Control"] = "no-store"
    return resp


@web.middleware
async def access_log(request: web.Request, handler):
    print(f"[bootstrap] {request.method} {request.path}", flush=True)
    return await handler(request)


async def health(_: web.Request) -> web.Response:
    return _no_store(web.json_response({"ok": True, "version": VERSION}))


async def ca_crt(_: web.Request) -> web.Response:
    try:
        pem = CA_CERT_PATH.read_bytes()
    except FileNotFoundError:
        return _no_store(web.Response(status=503, text="CA not yet generated\n"))
    return _no_store(web.Response(body=pem, content_type="application/x-pem-file"))


async def bootstrap_sh(_: web.Request) -> web.Response:
    return _no_store(web.Response(body=BOOTSTRAP_SH, content_type="text/x-shellscript"))


async def env_sh(_: web.Request) -> web.Response:
    return _no_store(web.Response(body=ENV_SH, content_type="text/x-shellscript"))


async def setup(_: web.Request) -> web.Response:
    return _no_store(
        web.json_response(
            {"ca_url": "http://proxy.local/ca.crt", "env": CA_ENV, "version": VERSION}
        )
    )


async def domains(request: web.Request) -> web.Response:
    creds = request.app[CREDS_KEY]
    return _no_store(web.json_response({"intercept": sorted(creds.intercept_hosts())}))


async def tokens(request: web.Request) -> web.Response:
    creds = request.app[CREDS_KEY]
    return _no_store(web.json_response(creds.workspace_tokens()))


async def llms_txt(_: web.Request) -> web.Response:
    return _no_store(
        web.Response(body=LLMS_TXT, content_type="text/plain", charset="utf-8")
    )


def make_app(creds: Credentials) -> web.Application:
    app = web.Application(middlewares=[access_log])
    app[CREDS_KEY] = creds
    app.router.add_get("/health", health)
    app.router.add_get("/ca.crt", ca_crt)
    app.router.add_get("/bootstrap.sh", bootstrap_sh)
    app.router.add_get("/env.sh", env_sh)
    app.router.add_get("/setup", setup)
    app.router.add_get("/domains", domains)
    app.router.add_get("/tokens", tokens)
    app.router.add_get("/llms.txt", llms_txt)
    return app
