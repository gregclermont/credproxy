"""Proxy entrypoint: mitmproxy (transparent) + bootstrap HTTP API.

Two listeners on one asyncio loop, in one Python process. The bash
supervisor watches the process; killing it stops both listeners and they
come back together on respawn.
"""
import asyncio
import sys

from aiohttp import web
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon
import bootstrap

PROXY_PORT = 39999
BOOTSTRAP_PORT = 39998


async def run() -> None:
    runner = web.AppRunner(bootstrap.make_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", BOOTSTRAP_PORT).start()
    print(
        f"[main] bootstrap API listening on 127.0.0.1:{BOOTSTRAP_PORT}",
        flush=True,
    )

    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        mode=["transparent"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(addon.HostnameLogger())
    print(
        f"[main] mitmproxy listening on 127.0.0.1:{PROXY_PORT} (transparent)",
        flush=True,
    )

    try:
        await master.run()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)
