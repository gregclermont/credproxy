"""Starlark script registry for scripted injectors.

A *scripted injector* (an injector with `scheme = "script"`) names a `.star`
file that defines `on_request`/`on_response`. The host CLI resolves the file
here and reads its SOURCE; the source is pushed to the proxy in the wire config
(the push model -- the proxy stays stateless and compiles what it is given, so
user scripts work with no mounts or image rebuilds). The proxy sandboxes
execution; see `proxy/starlark_runtime.py`.

Discovery (first match wins, user shadows builtin):
  1. $XDG_CONFIG_HOME/credproxy/scripts/<name>.star
  2. builtin  cli/credproxy_cli/builtin/scripts/<name>.star
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import InjectorError
from .paths import layered_dirs


@dataclass(frozen=True)
class Script:
    name: str
    source: str
    source_origin: str  # "user" / "profile" / "builtin" -- diagnostics / `list`


def find_script(name: str) -> Script:
    """Resolve a `.star` script by name and read its source across the layered
    registry (user > profile > builtin). Raises InjectorError if not found."""
    searched = layered_dirs("scripts")
    for origin, base in searched:
        path = base / f"{name}.star"
        if path.is_file():
            return Script(name=name, source=path.read_text(), source_origin=origin)
    where = ", ".join(str(b) for _, b in searched)
    raise InjectorError(
        f"script '{name}' not found (looked for {name}.star in {where})"
    )


def list_scripts() -> list[Script]:
    """All resolvable scripts, user shadowing profile shadowing builtin, sorted
    by name."""
    seen: dict[str, Script] = {}
    for origin, base in reversed(layered_dirs("scripts")):
        if not base.is_dir():
            continue
        for path in base.iterdir():
            if path.suffix == ".star" and path.is_file():
                seen[path.stem] = Script(path.stem, path.read_text(), origin)
    return [seen[n] for n in sorted(seen)]
