"""Proxy entrypoint: mitmproxy (transparent) + merged HTTP API.

Two listeners on one asyncio loop:

- mitmproxy on 127.0.0.1:39999 (transparent intercept).
- aiohttp on 0.0.0.0:39998 -- admin routes (TOFU + bearer) and
  bootstrap routes (workspace-facing, open) on the same listener.

State (auth token + config) lives on tmpfs at /run/secrets/{auth.token,
config.json}. Both files absent at first start -> TOFU: the host CLI's
first POST /admin/config sets both. Python respawns within the same
container reload state from tmpfs; full container restart returns the
proxy to TOFU. The bash supervisor restarts python on death.
"""
import asyncio
import sys

from aiohttp import web
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon
import admin
import bootstrap

PROXY_PORT = 39999  # mitmproxy transparent intercept


def make_http_app(state: admin.AppState) -> web.Application:
    app = web.Application(
        middlewares=[admin.no_store, admin.access_log, admin.fetch_metadata_guard]
    )
    app[admin.STATE_KEY] = state
    app.router.add_routes(admin.admin_routes)
    app.router.add_routes(bootstrap.bootstrap_routes)
    return app


async def run() -> None:
    state = admin.load_initial_state()
    print(
        f"[main] state: intercept_hosts={sorted(state.creds.intercept_hosts())}",
        flush=True,
    )

    http_runner = web.AppRunner(make_http_app(state), access_log=None)
    await http_runner.setup()
    await web.TCPSite(http_runner, "0.0.0.0", admin.HTTP_PORT).start()
    print(
        f"[main] HTTP API listening on 0.0.0.0:{admin.HTTP_PORT}",
        flush=True,
    )

    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        mode=["transparent"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(addon.HostnameLogger(state))
    print(
        f"[main] mitmproxy listening on 127.0.0.1:{PROXY_PORT} (transparent)",
        flush=True,
    )

    try:
        await master.run()
    finally:
        await http_runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)
