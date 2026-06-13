"""Talking to the proxy's HTTP API over the published 127.0.0.1 port.

Pushing config materializes the workspace's bindings, fetches each binding's
real secret from its provider, maps them onto the bindings wire shape, and
POSTs to /admin/config with the workspace's bearer token. Failures raise
ProxyError (connect / readiness / 401 / non-200).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Callable

from .bindings import materialize_bindings, wire_config
from .errors import ProxyError
from .workspace import Workspace, read_token

Notify = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


def _http_post_json(url: str, body: bytes, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw}
    except urllib.error.URLError as e:
        raise ProxyError(f"connect error talking to the proxy: {e.reason}")


def wait_for_ready(http_port: int, timeout: float = 15.0) -> None:
    """Poll /health until the proxy answers 200 or `timeout` elapses."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{http_port}/health", timeout=1
            ) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            last_err = e
        time.sleep(0.1)
    raise ProxyError(
        f"proxy did not become ready within {timeout:.0f}s ({last_err})"
    )


def push_config(ws: Workspace, http_port: int, notify: Notify = _noop):
    """Materialize bindings, fetch each secret from its provider, and POST
    the resulting wire config to /admin/config.

    Materialization may rewrite the config file (filling in generated
    names/placeholders); that is announced via `notify`.

    Returns the list of materialized Binding instances so the caller can
    record applied-bindings.json."""
    token = read_token(ws)
    bindings = materialize_bindings(ws, notify)
    body = json.dumps(wire_config(bindings)).encode()
    status, payload = _http_post_json(
        f"http://127.0.0.1:{http_port}/admin/config", body, token
    )
    if status == 200:
        return bindings
    if status == 401:
        raise ProxyError(
            f"proxy rejected the token (HTTP 401); check {ws.token_path}"
        )
    raise ProxyError(
        f"config push failed: HTTP {status}: {payload.get('error', payload)}"
    )
