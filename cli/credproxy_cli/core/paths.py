"""Repo layout and CLI-only conventions.

These are names the CLI picks for itself (image tag, default workspace
image) -- they don't need to match anything in the proxy image. The
image's own API (ports, mount targets) is read separately from
`docker inspect` in imageenv.py.

Storage follows XDG:
  - Config:  $XDG_CONFIG_HOME/credproxy/   (default ~/.config/credproxy/)
  - State:   $XDG_STATE_HOME/credproxy/    (default ~/.local/state/credproxy/)

Use the XDG env vars to override (works for tests too).
"""
from __future__ import annotations

import os
from pathlib import Path

# Repo layout: this package lives at <repo>/cli/credproxy_cli. The proxy
# source tree is needed only by the `dev` harness commands and for the
# dev-mode source bind-mount into the proxy container.
REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_DIR = REPO_ROOT / "proxy"
TESTS_DIR = REPO_ROOT / "tests"


def _xdg_config_home() -> Path:
    """XDG_CONFIG_HOME, defaulting to ~/.config. Read at call time so
    tests can override the env var before any call."""
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def _xdg_state_home() -> Path:
    """XDG_STATE_HOME, defaulting to ~/.local/state. Read at call time so
    tests can override the env var before any call."""
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))


def config_dir() -> Path:
    """Root config dir: $XDG_CONFIG_HOME/credproxy/."""
    return _xdg_config_home() / "credproxy"


def profile_dir() -> Path:
    """The distribution/org *profile* overlay: the middle tier between the
    end-user's XDG config and the in-package `builtin` defaults. Holds an org's
    customized scaffold, constants, and definitions (injectors/providers/
    scripts/presets) -- see docs/forking.md.

    Defaults to `<repo>/profile/` (a directory upstream ships empty, so a fork
    only ever ADDS files there and never conflicts on merge). Override with
    `CREDPROXY_PROFILE_DIR` to point at an external bundle -- the no-fork path,
    and what tests use. Read at call time so the env var can change per test."""
    env = os.environ.get("CREDPROXY_PROFILE_DIR")
    return Path(env) if env else REPO_ROOT / "profile"


def workspaces_config_dir() -> Path:
    """Directory that holds per-workspace TOML files."""
    return config_dir() / "workspaces"


def providers_config_dir() -> Path:
    """User provider registry: $XDG_CONFIG_HOME/credproxy/providers/."""
    return config_dir() / "providers"


def injectors_config_dir() -> Path:
    """User injector registry: $XDG_CONFIG_HOME/credproxy/injectors/."""
    return config_dir() / "injectors"


def scripts_config_dir() -> Path:
    """User Starlark-script registry: $XDG_CONFIG_HOME/credproxy/scripts/.
    Scripts back a scripted injector (scheme = "script"); the CLI reads the
    .star source and pushes it to the proxy."""
    return config_dir() / "scripts"


# Builtin definitions ship in the package; they double as scaffold templates.
BUILTIN_DIR = Path(__file__).resolve().parent.parent / "builtin"


def builtin_providers_dir() -> Path:
    return BUILTIN_DIR / "providers"


def builtin_injectors_dir() -> Path:
    return BUILTIN_DIR / "injectors"


def builtin_scripts_dir() -> Path:
    return BUILTIN_DIR / "scripts"


def builtin_presets_dir() -> Path:
    return BUILTIN_DIR / "presets"


# Singleton distribution assets (one file; the profile overlay overrides it).
def builtin_workspace_template_file() -> Path:
    """Built-in workspace scaffold frame."""
    return BUILTIN_DIR / "workspace.template.toml"


def resolve_singleton(filename: str) -> Path | None:
    """A singleton distribution file (profile.toml, workspace.template.toml):
    the profile overlay's copy if present, else the builtin default, else None."""
    cand = profile_dir() / filename
    if cand.is_file():
        return cand
    cand = BUILTIN_DIR / filename
    return cand if cand.is_file() else None


def layered_dirs(kind: str) -> list[tuple[str, Path]]:
    """The ordered search path for a *registry* asset kind (`injectors`,
    `providers`, `scripts`, `presets`), most specific first:

        user (XDG)  ->  profile (org overlay)  ->  builtin (upstream default)

    First match wins, so the profile overlay shadows a builtin definition of
    the same name and a user definition shadows both. The single seam every
    `find_*`/`list_*` walks, so the three (now four) registries stay in sync."""
    return [
        ("user", config_dir() / kind),
        ("profile", profile_dir() / kind),
        ("builtin", BUILTIN_DIR / kind),
    ]


def state_dir() -> Path:
    """Root state dir: $XDG_STATE_HOME/credproxy/."""
    return _xdg_state_home() / "credproxy"


def workspaces_state_dir() -> Path:
    """Directory that holds per-workspace state subdirs."""
    return state_dir() / "workspaces"


# CLI-only conventions.
IMAGE_TAG = "credproxy:dev"          # the proxy image the CLI builds/runs
DEFAULT_WORKSPACE = "default"
# Fallback home (mount target) when a workspace omits `home`. The workspace
# *image* is mandatory (no default) -- the scaffold writes a concrete one, and
# `load_config` errors if it's missing -- so the default workspace image lives in
# exactly one visible place: builtin/workspace.template.toml (overridable by the
# profile overlay). The home target, by contrast, has a sensible universal.
DEFAULT_HOME = "/root"
