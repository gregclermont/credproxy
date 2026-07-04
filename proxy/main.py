"""Proxy entrypoint: mitmproxy (transparent) + merged HTTP API.

Two listeners on one asyncio loop:

- mitmproxy on 127.0.0.1:39999 (transparent intercept).
- aiohttp on 0.0.0.0:39998 -- admin routes (bearer-gated) and
  bootstrap routes (workspace-facing, open) on the same listener.

The auth token is bind-mounted at /run/secrets-ro/auth.token from the
host; admin.py reads it fresh per request, so host-side rotation
takes effect without a restart. Config lives on tmpfs at
/run/secrets/config.json, written by POST /admin/config. On SIGHUP
(triggered by `credproxy reload`) python re-execs itself in place;
the container, its netns/iptables, and tmpfs survive, so pushed
config persists across reloads. A python crash takes the container
down (no supervisor) -- full container restart drops the config and
the host re-pushes via `credproxy config`.
"""
import asyncio
import os
import signal
import sys

from aiohttp import web
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon
import admin
import bootstrap
import log
from constants import HTTP_PORT, PROXY_PORT


def make_http_app(state: admin.AppState) -> web.Application:
    app = web.Application(
        middlewares=[admin.no_store, admin.access_log, admin.fetch_metadata_guard]
    )
    app[admin.STATE_KEY] = state
    app.router.add_routes(admin.admin_routes)
    app.router.add_routes(bootstrap.bootstrap_routes)
    return app


def _reload() -> None:
    log.emit("main", msg="SIGHUP -- re-execing")
    os.execv(sys.executable, [sys.executable, "-u", *sys.argv])


async def run() -> None:
    asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, _reload)

    state = admin.load_initial_state()
    log.emit("main", msg="state",
             intercept_hosts=sorted(state.creds.intercept_hosts()))

    http_runner = web.AppRunner(make_http_app(state), access_log=None)
    await http_runner.setup()
    await web.TCPSite(http_runner, "0.0.0.0", HTTP_PORT).start()
    log.emit("main", msg=f"HTTP API listening on 0.0.0.0:{HTTP_PORT}")

    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        mode=["transparent"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(addon.HostnameLogger(state))
    log.emit("main",
             msg=f"mitmproxy listening on 127.0.0.1:{PROXY_PORT} (transparent)")

    try:
        await master.run()
    finally:
        await http_runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)
