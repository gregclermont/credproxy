"""Workspace config: load/validate <name>.toml, resolve ${secret:} refs,
and compute the workspace launch-spec hash.

Config is stored at $XDG_CONFIG_HOME/credproxy/workspaces/<name>.toml and
parsed with stdlib `tomllib` (Python 3.11+). No external dependencies.

Schema:
  image  = "python:3.12-slim"          # str, optional (default applied)
  home   = "/root"                     # str, optional (default applied)
  mounts = ["~/src:/src"]              # list[str] "SRC:DST" or "SRC:DST:ro"
  env    = { KEY = "value" }           # table, optional; passed as -e to ws
  setup  = ["npm ci"]                  # list[str], optional; run once on create

  [[binding]]                          # zero or more; see core/bindings.py
  injector = "bearer"
  provider = "env"
  secret   = "GITHUB_TOKEN"
  hosts    = ["api.github.com"]

The `[[binding]]` array is parsed/validated/materialized by core/bindings.py,
not here -- load_config only handles the container-side settings.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .errors import ConfigError
from .workspace import Workspace
from .paths import DEFAULT_HOME, DEFAULT_WORKSPACE_IMAGE

import tomllib

# TOML template scaffolded by `credproxy create`.
# Required: image (defaulted). Everything else is optional / commented out.
CONFIG_TEMPLATE = """\
# credproxy workspace config.
# Edit this file, then run `credproxy workspace {name} start` to apply.

# Workspace image. Changing this (or mounts/env/setup) recreates the
# workspace container on the next `start`.
image = "{image}"

# Where the persistent home volume mounts inside the workspace.
# home = "/root"

# User that `enter` runs as (docker exec -u). The user must exist in the
# image -- built in, or created by `setup` (which always runs as root, so it
# can `useradd` + chown the home volume). Exec-only: changing it never
# recreates the container, and `enter --user NAME` overrides it per session.
# user = "dev"

# Escape hatch: extra flags spliced into `docker exec` for `enter`
# (e.g. a working dir or env). credproxy keeps control of -i/-t/-d. Exec-only.
# exec_flags = ["--workdir", "/srv"]

# Host paths bind-mounted into the workspace. Each entry is
# "SRC:DST" or "SRC:DST:ro"; ~ is expanded on SRC.
# mounts = [
#   "~/code:/code",
# ]

# Extra environment variables injected into the workspace container.
# env = {{ GH_DEBUG = "1" }}

# Shell commands run on each freshly (re)created workspace container (as root),
# so make them idempotent. A failing command stops start and leaves the
# container for debugging.
# setup = [
#   "npm ci",
# ]

# Automatically stop the workspace when the last `enter` session exits.
# Off by default. Changing this mid-session takes effect immediately (live
# config edit). A stopped workspace is resumed automatically on the next `enter`.
# auto_stop = true

# Credential bindings. Each ties an injector (how a credential is shaped
# into a request) to a provider (where the value comes from), scoped to one
# or more hosts. The real secret never enters the workspace -- the proxy
# swaps the placeholder for the real value on requests to these hosts.
# Add them with `credproxy binding add` (or `--preset NAME` for a coordinated
# set like github -- see `credproxy preset list`), or uncomment and edit:
# [[binding]]
# injector = "bearer"            # a scheme; see `credproxy injector list`
# provider = "env"               # a value source; see `credproxy provider list`
# secret   = "GITHUB_TOKEN"      # ref the provider resolves (env: a host env var name)
# hosts    = ["api.github.com"]
# name + placeholder + env are auto-generated; override here if needed.
"""


def load_config(ws: Workspace) -> dict:
    """Parse and validate the container-side settings of <name>.toml into a
    normalized dict: {image, home, mounts: [{source, target, readonly}],
    env: {}, setup: []}. The `[[binding]]` array is handled separately by
    core/bindings.py."""
    if not ws.exists():
        raise ConfigError(
            f"workspace '{ws.name}' not found (no {ws.config_path})"
        )
    try:
        raw = tomllib.loads(ws.config_path.read_text())
    except Exception as e:
        raise ConfigError(f"{ws.config_path}: TOML parse error: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"{ws.config_path}: top level must be a table")

    # image
    image = raw.get("image") or DEFAULT_WORKSPACE_IMAGE
    if not isinstance(image, str):
        raise ConfigError(f"{ws.config_path}: `image` must be a string")

    # home
    home = raw.get("home") or DEFAULT_HOME
    if not isinstance(home, str) or not home.startswith("/"):
        raise ConfigError(f"{ws.config_path}: `home` must be an absolute path")

    # mounts: list of "SRC:DST" or "SRC:DST:ro" strings
    mounts = []
    raw_mounts = raw.get("mounts") or []
    if not isinstance(raw_mounts, list):
        raise ConfigError(f"{ws.config_path}: `mounts` must be an array")
    for i, m in enumerate(raw_mounts):
        if not isinstance(m, str):
            raise ConfigError(
                f"{ws.config_path}: mounts[{i}] must be a string (\"SRC:DST\" or \"SRC:DST:ro\")"
            )
        parts = m.split(":")
        if len(parts) < 2 or len(parts) > 3:
            raise ConfigError(
                f"{ws.config_path}: mounts[{i}]: expected \"SRC:DST\" or \"SRC:DST:ro\", got {m!r}"
            )
        src = Path(os.path.expanduser(parts[0]))
        if not src.is_absolute():
            raise ConfigError(
                f"{ws.config_path}: mounts[{i}] source must be absolute "
                f"(after ~ expansion): {parts[0]!r}"
            )
        if not src.exists():
            raise ConfigError(
                f"{ws.config_path}: mounts[{i}] source does not exist: {src}"
            )
        target = parts[1]
        if not target.startswith("/"):
            raise ConfigError(
                f"{ws.config_path}: mounts[{i}] target must be absolute: {target!r}"
            )
        readonly = len(parts) == 3 and parts[2] == "ro"
        mounts.append({
            "source": str(src),
            "target": target,
            "readonly": readonly,
        })

    # env: inline table of string values
    env = raw.get("env") or {}
    if not isinstance(env, dict):
        raise ConfigError(f"{ws.config_path}: `env` must be a table")
    for k, v in env.items():
        if not isinstance(k, str):
            raise ConfigError(f"{ws.config_path}: `env` keys must be strings")
        if not isinstance(v, str):
            raise ConfigError(
                f"{ws.config_path}: env.{k} must be a string, got {type(v).__name__}"
            )

    # setup: list of shell command strings
    setup = raw.get("setup") or []
    if not isinstance(setup, list):
        raise ConfigError(f"{ws.config_path}: `setup` must be an array")
    for i, cmd in enumerate(setup):
        if not isinstance(cmd, str):
            raise ConfigError(
                f"{ws.config_path}: setup[{i}] must be a string"
            )

    # user: optional user that `enter` execs as (docker exec -u). Exec-only, so
    # NOT part of the spec hash -- changing it never recreates the container; it
    # takes effect on the next `enter`. The user must exist in the image (built
    # in or created by `setup`, which always runs as root).
    user = raw.get("user")
    if user is not None and (not isinstance(user, str) or not user):
        raise ConfigError(f"{ws.config_path}: `user` must be a non-empty string")

    # exec_flags: escape hatch -- extra flags spliced into `docker exec` for
    # `enter` (e.g. ["--workdir", "/srv"], ["--env", "FOO=bar"]). credproxy keeps
    # ownership of the session-control flags (-i/-t/-d), so these can't break
    # session tracking. Exec-only, like `user`; not part of the spec.
    exec_flags = raw.get("exec_flags") or []
    if not isinstance(exec_flags, list) or not all(isinstance(f, str) for f in exec_flags):
        raise ConfigError(f"{ws.config_path}: `exec_flags` must be an array of strings")

    return {
        "image": image,
        "home": home,
        "mounts": mounts,
        "env": env,
        "setup": setup,
        "user": user,
        "exec_flags": exec_flags,
    }


def quick_image(ws: Workspace) -> str:
    """Best-effort `image` read for `list`, without full validation."""
    try:
        raw = tomllib.loads(ws.config_path.read_text())
        return raw.get("image") or DEFAULT_WORKSPACE_IMAGE
    except Exception:
        return "?"


def workspace_spec_hash(cfg: dict, proxy_id: str | None) -> str:
    """Identity of the workspace container's launch spec. Changing the
    image, home, mounts, env, setup, or the proxy container (netns peer)
    yields a new hash, which `start` uses to decide whether to recreate."""
    spec = json.dumps(
        {
            "image": cfg["image"],
            "home": cfg["home"],
            "mounts": cfg["mounts"],
            "env": cfg["env"],
            "setup": cfg["setup"],
            "proxy": proxy_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(spec.encode()).hexdigest()[:16]


def render_template(name: str, image: str) -> str:
    return CONFIG_TEMPLATE.format(name=name, image=image)
