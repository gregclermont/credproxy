"""Sidecar entrypoint: mitmproxy as a library, transparent mode.

iptables in entrypoint.sh REDIRECTs all sandbox-side TCP egress here.
The addon (addon.py) handles SNI peeking and per-request logging.
"""
import asyncio
import sys

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon


async def run() -> None:
    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=39999,
        mode=["transparent"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(addon.HostnameLogger())
    print("[main] mitmproxy listening on 127.0.0.1:39999 (transparent)", flush=True)
    await master.run()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)
