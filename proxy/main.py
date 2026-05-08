"""Proxy entrypoint: mitmproxy (transparent) + bootstrap HTTP API + admin API.

Three listeners on one asyncio loop, in one Python process. The bash
supervisor watches the process; killing it stops all listeners and they
come back together on respawn.

Startup state arrives on stdin as a single JSON envelope:

    {"auth_token": "<random hex>", "secrets": {"NAME": "value", ...}}

The token gates the admin API (host-only, port 39997). Secrets are used
to resolve `${secret:NAME}` references in config.yaml. Both live only in
this process's heap -- never in os.environ, never on persistent disk.
The supervisor preserves them across reloads via a tmpfs file.
"""
import asyncio
import json
import os
import signal
import sys
from pathlib import Path

from aiohttp import web
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon
import admin
import bootstrap
import config

PROXY_PORT = 39999
BOOTSTRAP_PORT = 39998
ADMIN_PORT = 39997
SECRETS_PATH = Path("/run/secrets/secrets.json")
CONFIG_JSON_PATH = Path("/run/secrets/config.json")


def _load_startup() -> tuple[str, dict[str, str]]:
    """Parse the stdin envelope and return (auth_token, secrets).

    Strict shape: {"auth_token": str, "secrets": {str: str}}. Empty
    stdin is rejected -- a token is always required for the admin API.
    """
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit("[main] empty stdin; expected envelope JSON with auth_token")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"[main] invalid JSON on stdin: {e}")
    if not isinstance(data, dict):
        sys.exit(
            f"[main] stdin JSON must be an object, got {type(data).__name__}"
        )
    token = data.get("auth_token")
    if not isinstance(token, str) or not token:
        sys.exit("[main] envelope missing non-empty `auth_token` (string)")
    secrets_raw = data.get("secrets", {})
    if not isinstance(secrets_raw, dict):
        sys.exit(
            f"[main] envelope `secrets` must be an object, "
            f"got {type(secrets_raw).__name__}"
        )
    secrets: dict[str, str] = {}
    for k, v in secrets_raw.items():
        if not isinstance(k, str) or not k:
            sys.exit("[main] secret keys must be non-empty strings")
        if not isinstance(v, str):
            sys.exit(
                f"[main] secret {k!r} must be a string, "
                f"got {type(v).__name__}"
            )
        secrets[k] = v
    return token, secrets


async def run() -> None:
    auth_token, secrets = _load_startup()
    print(
        f"[main] loaded auth_token + {len(secrets)} secret(s): "
        f"{sorted(secrets)}",
        flush=True,
    )

    # Prefer the API-pushed config (already-resolved JSON) if present;
    # otherwise fall back to the bind-mounted config.yaml + secrets
    # resolution. The two paths coexist during the transition.
    try:
        if CONFIG_JSON_PATH.exists():
            creds = config.load_resolved(
                json.loads(CONFIG_JSON_PATH.read_text()),
                source=str(CONFIG_JSON_PATH),
            )
            print(f"[main] config from {CONFIG_JSON_PATH}", flush=True)
        else:
            creds = config.load(secrets)
            print(f"[main] config from {config.CONFIG_PATH}", flush=True)
    except config.ConfigError as e:
        sys.exit(str(e))
    print(
        f"[main] loaded config: {len(creds.intercept_hosts())} intercept "
        f"host(s): {sorted(creds.intercept_hosts())}",
        flush=True,
    )

    bootstrap_runner = web.AppRunner(bootstrap.make_app(creds), access_log=None)
    await bootstrap_runner.setup()
    await web.TCPSite(bootstrap_runner, "127.0.0.1", BOOTSTRAP_PORT).start()
    print(
        f"[main] bootstrap API listening on 127.0.0.1:{BOOTSTRAP_PORT}",
        flush=True,
    )

    # Admin app must bind 0.0.0.0 (not 127.0.0.1) so docker -p host->container
    # forwarding can reach it via the bridge interface. Workspace access via
    # the shared netns is blocked by the iptables rules installed in
    # entrypoint.sh (INPUT-on-lo + OUTPUT-uid).
    def trigger_reload() -> None:
        # Schedule SIGTERM after this event loop tick so the response from
        # the admin handler has time to flush. Supervisor catches the exit
        # and respawns python, which re-reads the secrets file.
        loop = asyncio.get_running_loop()
        loop.call_later(0.1, lambda: os.kill(os.getpid(), signal.SIGTERM))

    admin_runner = web.AppRunner(
        admin.make_admin_app(
            auth_token, SECRETS_PATH, CONFIG_JSON_PATH, trigger_reload
        ),
        access_log=None,
    )
    await admin_runner.setup()
    await web.TCPSite(admin_runner, "0.0.0.0", ADMIN_PORT).start()
    print(
        f"[main] admin API listening on 0.0.0.0:{ADMIN_PORT} (host-only)",
        flush=True,
    )

    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        mode=["transparent"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(addon.HostnameLogger(creds))
    print(
        f"[main] mitmproxy listening on 127.0.0.1:{PROXY_PORT} (transparent)",
        flush=True,
    )

    try:
        await master.run()
    finally:
        await bootstrap_runner.cleanup()
        await admin_runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)
