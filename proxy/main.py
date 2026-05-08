"""Proxy entrypoint: mitmproxy (transparent) + bootstrap HTTP API.

Two listeners on one asyncio loop, in one Python process. The bash
supervisor watches the process; killing it stops both listeners and they
come back together on respawn.

Secrets are passed in via stdin as a single JSON object of {NAME: value}
(populated by the supervisor from `docker run -i`). They live only in
this process's heap -- never in os.environ, never on disk -- and config
references them via `${secret:NAME}` in `real:` fields.
"""
import asyncio
import json
import sys

from aiohttp import web
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

import addon
import bootstrap
import config

PROXY_PORT = 39999
BOOTSTRAP_PORT = 39998


def _load_secrets() -> dict[str, str]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"[main] invalid JSON on stdin: {e}")
    if not isinstance(data, dict):
        sys.exit(
            f"[main] stdin JSON must be an object, got {type(data).__name__}"
        )
    for k, v in data.items():
        if not isinstance(k, str) or not k:
            sys.exit(f"[main] secret keys must be non-empty strings")
        if not isinstance(v, str):
            sys.exit(
                f"[main] secret {k!r} must be a string, "
                f"got {type(v).__name__}"
            )
    return data


async def run() -> None:
    secrets = _load_secrets()
    print(
        f"[main] loaded {len(secrets)} secret(s) from stdin: "
        f"{sorted(secrets)}",
        flush=True,
    )

    creds = config.load(secrets)
    print(
        f"[main] loaded config: {len(creds.intercept_hosts())} intercept "
        f"host(s): {sorted(creds.intercept_hosts())}",
        flush=True,
    )

    runner = web.AppRunner(bootstrap.make_app(creds), access_log=None)
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
    master.addons.add(addon.HostnameLogger(creds))
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
