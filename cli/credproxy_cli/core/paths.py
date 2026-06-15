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


# Bundled definitions ship in the package; they double as scaffold templates.
BUNDLED_DIR = Path(__file__).resolve().parent.parent / "bundled"


def bundled_providers_dir() -> Path:
    return BUNDLED_DIR / "providers"


def bundled_injectors_dir() -> Path:
    return BUNDLED_DIR / "injectors"


def bundled_scripts_dir() -> Path:
    return BUNDLED_DIR / "scripts"


def state_dir() -> Path:
    """Root state dir: $XDG_STATE_HOME/credproxy/."""
    return _xdg_state_home() / "credproxy"


def workspaces_state_dir() -> Path:
    """Directory that holds per-workspace state subdirs."""
    return state_dir() / "workspaces"


# CLI-only conventions.
IMAGE_TAG = "credproxy:dev"
DEFAULT_WORKSPACE = "default"
# The default workspace image is a devcontainers base: it ships a non-root sudo
# user (`vscode`, uid 1000) plus curl + ca-certificates, so the documented
# bootstrap (`curl ... | sh`) and a non-root shell work with no setup. The
# scaffold wires up the matching `user`/`home` when this image is the default
# (see render_template); a `--image` override falls back to the generic, all-
# commented template since its user is unknown.
DEFAULT_WORKSPACE_IMAGE = "mcr.microsoft.com/devcontainers/base:ubuntu"
DEFAULT_WORKSPACE_USER = "vscode"
DEFAULT_WORKSPACE_USER_HOME = "/home/vscode"
DEFAULT_HOME = "/root"  # generic fallback when `home` is omitted (custom images)
