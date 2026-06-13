"""Scaffold a user injector/provider from a bundled template.

Bundled definitions double as starting points: `scaffold` copies one into the
user registry under a new name so you can author from it. Filesystem-native --
the copied file IS the registry entry, referenced by name.
"""
from __future__ import annotations

import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import CredproxyError
from .paths import (
    bundled_injectors_dir,
    bundled_providers_dir,
    injectors_config_dir,
    providers_config_dir,
)

# Which bundled definition seeds each kind of scaffold.
_INJECTOR_TEMPLATE = "bearer"  # generic bearer injector
_PROVIDER_TEMPLATE = "env"     # env-var provider script


@dataclass(frozen=True)
class ScaffoldResult:
    kind: str   # "injector" | "provider"
    name: str
    path: Path


def scaffold(kind: str, name: str) -> ScaffoldResult:
    """Copy the bundled template for `kind` into the user registry as `name`.

    Refuses to overwrite an existing file. Returns the destination path."""
    if kind == "injector":
        src = bundled_injectors_dir() / f"{_INJECTOR_TEMPLATE}.toml"
        dst_dir = injectors_config_dir()
        dst = dst_dir / f"{name}.toml"
    elif kind == "provider":
        src = bundled_providers_dir() / _PROVIDER_TEMPLATE
        dst_dir = providers_config_dir()
        dst = dst_dir / name
    else:
        raise CredproxyError(f"unknown scaffold kind {kind!r}")

    if dst.exists():
        raise CredproxyError(f"{dst} already exists; refusing to overwrite")
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    if kind == "provider":
        # Preserve the executable bit so the copy is directly runnable.
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return ScaffoldResult(kind=kind, name=name, path=dst)
