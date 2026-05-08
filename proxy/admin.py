"""Admin HTTP API: host-only management endpoints.

Served on 0.0.0.0:39997 inside the proxy's netns. Two access patterns:

1. From the host: docker -p 127.0.0.1:39997:39997 forwards host loopback
   to the container; arrives via the netns INPUT chain.
2. From the workspace: blocked by iptables rules installed in
   entrypoint.sh -- INPUT on lo for dport 39997 (load-bearing) plus
   OUTPUT --uid-owner (defense-in-depth). Workspace traffic to either
   127.0.0.1 or the bridge IP routes via lo (kernel local-IP shortcut),
   so the INPUT-on-lo filter nails it.

All routes under /admin/* require `Authorization: Bearer <token>`,
matched against the auth_token passed in via the stdin envelope at
startup. The token lives only in the proxy's heap and (host-side) in
.run/auth.token, mode 0600.

Mutations (POST /admin/secrets) write to the same tmpfs file the
supervisor pipes into each python spawn (see supervisor.sh), then
trigger a reload via an injected reload_fn. The reload mechanism is
SIGTERM-self in production; tests inject a no-op or sentinel.
"""
import hmac
import json
import os
import re
from pathlib import Path
from typing import Callable

from aiohttp import web

import config

TOKEN_KEY = web.AppKey("auth_token", str)
SECRETS_PATH_KEY = web.AppKey("secrets_path", Path)
CONFIG_PATH_KEY = web.AppKey("config_path", Path)
RELOAD_FN_KEY = web.AppKey("reload_fn", Callable[[], None])

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _unauthorized(detail: str = "missing or invalid token") -> web.Response:
    return web.Response(status=401, text=f"unauthorized: {detail}\n")


@web.middleware
async def bearer_auth(request: web.Request, handler):
    expected = request.app[TOKEN_KEY]
    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme != "Bearer" or not presented:
        return _unauthorized("expected `Authorization: Bearer <token>`")
    if not hmac.compare_digest(presented, expected):
        return _unauthorized()
    return await handler(request)


async def health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True})


async def set_secret(request: web.Request) -> web.Response:
    """POST /admin/secrets — body: {"name": "X", "value": "..."}.

    Atomic-write into the envelope's `.secrets` sub-object, then trigger
    reload. Preserves auth_token at the top level so the supervisor's
    re-pipe of this file into the next python spawn keeps working.
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    if not isinstance(body, dict):
        return web.json_response({"error": "body must be a JSON object"}, status=400)

    name = body.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        return web.json_response(
            {"error": f"name must match {NAME_RE.pattern}"}, status=400
        )
    value = body.get("value")
    if not isinstance(value, str) or not value:
        return web.json_response(
            {"error": "value must be a non-empty string"}, status=400
        )

    _write_secret(request.app[SECRETS_PATH_KEY], name, value)
    request.app[RELOAD_FN_KEY]()
    return web.json_response({"ok": True, "name": name, "reloading": True})


def _write_secret(path: Path, name: str, value: str) -> None:
    """Read existing envelope, mutate .secrets[name]=value, atomic write."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    secrets = data.get("secrets")
    if not isinstance(secrets, dict):
        secrets = {}
        data["secrets"] = secrets
    secrets[name] = value

    tmp = str(path) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


async def set_config(request: web.Request) -> web.Response:
    """POST /admin/config — body is the full resolved config.

    Same shape as `config.yaml` but with literal `real:` values (no
    `${secret:NAME}` references — caller resolves before posting).
    Validated server-side via config.load_resolved; on success, atomic-
    write to /run/secrets/config.json and trigger reload. main.py
    prefers this file over the bind-mounted YAML if it exists.
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    try:
        config.load_resolved(body, source="POST /admin/config")
    except config.ConfigError as e:
        return web.json_response({"error": str(e)}, status=400)

    _write_atomic_json(request.app[CONFIG_PATH_KEY], body)
    request.app[RELOAD_FN_KEY]()
    return web.json_response({"ok": True, "reloading": True})


def _write_atomic_json(path: Path, data: object) -> None:
    tmp = str(path) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def make_admin_app(
    auth_token: str,
    secrets_path: Path,
    config_path: Path,
    reload_fn: Callable[[], None] = lambda: None,
) -> web.Application:
    app = web.Application(middlewares=[bearer_auth])
    app[TOKEN_KEY] = auth_token
    app[SECRETS_PATH_KEY] = secrets_path
    app[CONFIG_PATH_KEY] = config_path
    app[RELOAD_FN_KEY] = reload_fn
    app.router.add_get("/admin/health", health)
    app.router.add_post("/admin/secrets", set_secret)
    app.router.add_post("/admin/config", set_config)
    return app
