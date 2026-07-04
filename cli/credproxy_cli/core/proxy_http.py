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


def proxy_status(ws: Workspace, http_port: int) -> dict | None:
    """GET /admin/config: returns {"loaded": bool, "fingerprint": str|None}, or
    None if the proxy can't be reached or doesn't answer 200. Callers treat
    None as 'can't confirm -> push'."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{http_port}/admin/config",
        headers={"Authorization": f"Bearer {read_token(ws)}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode())
                return payload if isinstance(payload, dict) else None
    except (urllib.error.URLError, json.JSONDecodeError, ConnectionError,
            TimeoutError, OSError):
        return None
    return None


def rule_test_live(ws: Workspace, http_port: int, method: str, url: str) -> dict:
    """POST /admin/rule-test: the running proxy's authoritative rule dry-run for
    (method, url) against its LOADED config -- exact per-script phase + the
    intercept decision. Raises ProxyError on 401/non-200/connect failure."""
    status, payload = _http_post_json(
        f"http://127.0.0.1:{http_port}/admin/rule-test",
        json.dumps({"method": method, "url": url}).encode(),
        read_token(ws),
    )
    if status == 200:
        return payload
    if status == 401:
        raise ProxyError(
            f"proxy rejected the token (HTTP 401); check {ws.token_path}")
    raise ProxyError(
        f"proxy rule-test failed (HTTP {status}): {payload.get('error', payload)}")


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


def push_config(ws: Workspace, http_port: int, notify: Notify = _noop,
                bindings=None, rules=None, fingerprint=None):
    """Materialize bindings + rules, fetch each secret from its provider, and
    POST the resulting wire config (bindings + rules + a metadata `fingerprint`)
    to /admin/config.

    `bindings`/`rules`/`fingerprint` may be supplied by the caller (the start
    path computes them to decide whether a push is even needed); otherwise they
    are materialized/computed here. Materialization may rewrite the config file
    (filling generated names/placeholders); announced via `notify`.

    Returns `(bindings, rules)` (the materialized instances) so the caller can
    record applied-bindings.json / applied-rules.json."""
    from .rules import (combined_fingerprint, materialize_rules,
                        rule_wire_entries)

    token = read_token(ws)
    if bindings is None:
        bindings = materialize_bindings(ws, notify)
    if rules is None:
        rules = materialize_rules(ws, notify)
    if fingerprint is None:
        fingerprint = combined_fingerprint(bindings, rules)
    wire = wire_config(bindings)
    wire["rules"] = rule_wire_entries(rules)
    wire["fingerprint"] = fingerprint
    body = json.dumps(wire).encode()
    status, payload = _http_post_json(
        f"http://127.0.0.1:{http_port}/admin/config", body, token
    )
    if status == 200:
        return bindings, rules
    if status == 401:
        raise ProxyError(
            f"proxy rejected the token (HTTP 401); check {ws.token_path}"
        )
    raise ProxyError(
        f"config push failed: HTTP {status}: {payload.get('error', payload)}"
    )
