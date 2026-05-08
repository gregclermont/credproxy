"""Proxy entrypoint: mitmproxy (transparent) + bootstrap HTTP API + admin API.

Three listeners on one asyncio loop, in one Python process. The bash
supervisor watches the process; killing it stops all listeners and they
come back together on respawn.

Startup state arrives on stdin as a single JSON envelope:

    {"auth_token": "<random hex>"}

The token gates the admin API (host-only, port 39997). Configuration
arrives via POST /admin/config (resolved JSON, written to
/run/secrets/config.json on tmpfs); the host CLI `bin/credproxy
push-config` is the supported producer. If no config has been pushed
yet, the proxy starts with an empty intercept set -- everything passes
through and is logged. Run `make set-config` to push one.
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
CONFIG_JSON_PATH = Path("/run/secrets/config.json")


def _load_auth_token() -> str:
    """Parse the stdin envelope and return the bearer token.

    Strict shape: {"auth_token": "<non-empty string>"}. Anything else is
    a hard exit -- the admin API isn't safe to expose without auth.
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
    return token


def _load_creds() -> config.Credentials:
    """Load the proxy's resolved config from /run/secrets/config.json.

    Empty Credentials is the legitimate startup state when no config has
    been pushed yet -- the admin API stays up so the user can push one.
    """
    if not CONFIG_JSON_PATH.exists():
        print(
            f"[main] no config at {CONFIG_JSON_PATH}; "
            f"starting with empty intercept set. Run `make set-config`.",
            flush=True,
        )
        return config.YamlCredentials({})
    try:
        return config.load_resolved(
            json.loads(CONFIG_JSON_PATH.read_text()),
            source=str(CONFIG_JSON_PATH),
        )
    except config.ConfigError as e:
        sys.exit(str(e))


async def run() -> None:
    auth_token = _load_auth_token()
    print("[main] loaded auth_token", flush=True)

    creds = _load_creds()
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
        # and respawns python, which re-reads the config file.
        loop = asyncio.get_running_loop()
        loop.call_later(0.1, lambda: os.kill(os.getpid(), signal.SIGTERM))

    admin_runner = web.AppRunner(
        admin.make_admin_app(auth_token, CONFIG_JSON_PATH, trigger_reload),
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
