"""Runtime constants -- parsed from constants.sh, the single source of truth.

constants.sh is sourced by entrypoint.sh; this module parses it so Python
sees the same values without manual sync. The shell file is restricted to
plain `KEY=VALUE` lines (no `export`, no command substitution); this parser
matches that contract.
"""
from pathlib import Path

_c: dict[str, str] = {}
for _line in (Path(__file__).with_name("constants.sh")).read_text().splitlines():
    _line = _line.strip()
    if not _line or _line.startswith("#"):
        continue
    _k, _, _v = _line.partition("=")
    _c[_k.strip()] = _v.strip()

MITMPROXY_UID = int(_c["MITMPROXY_UID"])
HTTP_PORT = int(_c["HTTP_PORT"])
PROXY_PORT = int(_c["PROXY_PORT"])
SENTINEL_IP = _c["SENTINEL_IP"]
