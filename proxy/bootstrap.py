"""Bootstrap HTTP API.

Served on 127.0.0.1:39998. iptables redirects sentinel-IP:80 here so the
agent can `curl http://proxy.local/<endpoint>`. Plain HTTP is fine: the
shared netns has no eavesdropper.
"""
from pathlib import Path

from aiohttp import web

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
set -eu
CA_PATH=/tmp/proxy-ca.crt
curl -sf -o "$CA_PATH" http://proxy.local/ca.crt

export SSL_CERT_FILE="$CA_PATH"
export REQUESTS_CA_BUNDLE="$CA_PATH"
export NODE_EXTRA_CA_CERTS="$CA_PATH"
export GIT_SSL_CAINFO="$CA_PATH"
export CARGO_HTTP_CAINFO="$CA_PATH"
export AWS_CA_BUNDLE="$CA_PATH"

if command -v update-ca-certificates >/dev/null 2>&1; then
  cp "$CA_PATH" /usr/local/share/ca-certificates/proxy.crt 2>/dev/null \\
    && update-ca-certificates >/dev/null 2>&1 || true
fi

echo "Bootstrap complete. CA installed at $CA_PATH."
"""

ENV_SH = "".join(f'export {k}="{v}"\n' for k, v in CA_ENV.items())

LLMS_TXT = """\
This sandbox runs behind a transparent egress proxy.

Bootstrap (do this once, in your shell):

    eval "$(curl -s http://proxy.local/env.sh)"
    curl -sf http://proxy.local/ca.crt -o /tmp/proxy-ca.crt

After that, HTTPS to configured hosts will receive credential headers
automatically. You won't see the secrets.

If proxy.local does not resolve, use 169.254.1.1 directly.

Endpoints (all GET):
  /health        liveness probe (json)
  /ca.crt        CA certificate (PEM)
  /bootstrap.sh  shell script: download CA + export env vars
  /env.sh        env-var exports only
  /setup         JSON: ca_url, env, version
  /domains       JSON: configured inject hosts (currently none)
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


async def domains(_: web.Request) -> web.Response:
    return _no_store(web.json_response({"inject": []}))


async def llms_txt(_: web.Request) -> web.Response:
    return _no_store(
        web.Response(body=LLMS_TXT, content_type="text/plain", charset="utf-8")
    )


def make_app() -> web.Application:
    app = web.Application(middlewares=[access_log])
    app.router.add_get("/health", health)
    app.router.add_get("/ca.crt", ca_crt)
    app.router.add_get("/bootstrap.sh", bootstrap_sh)
    app.router.add_get("/env.sh", env_sh)
    app.router.add_get("/setup", setup)
    app.router.add_get("/domains", domains)
    app.router.add_get("/llms.txt", llms_txt)
    return app
