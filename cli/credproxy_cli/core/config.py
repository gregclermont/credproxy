"""Workspace config: load/validate <name>.toml, resolve ${secret:} refs,
and compute the workspace launch-spec hash.

Config is stored at $XDG_CONFIG_HOME/credproxy/workspaces/<name>.toml and
parsed with stdlib `tomllib` (Python 3.11+). No external dependencies.

Schema:
  image  = "mcr.microsoft.com/devcontainers/base:ubuntu"  # str, optional (default)
  home   = "/root"                     # str, optional (default applied)
  mounts = ["~/src:/src"]              # list[str] "SRC:DST" or "SRC:DST:ro"
  env    = { KEY = "value" }           # table, optional; passed as -e to ws
  setup  = ["npm ci"]                  # list[str], optional; run once on create
  run_flags = ["--userns=keep-id"]     # list[str], optional; spliced into docker run
  map_host_user = true                 # bool, optional; non-root `user` owns mounts
  user_uid = 1000                      # int, optional; in-container uid of `user`
  user   = "dev"                       # str, optional; user `enter` execs as
  shell  = ["zsh"]                     # list[str], optional; default `enter` command
  workdir = "/code"                    # str, optional; dir `enter` starts in
  enter_prelude = "..."                # str, optional; shell run before exec on enter

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
from .paths import (
    DEFAULT_HOME,
    DEFAULT_WORKSPACE_IMAGE,
    DEFAULT_WORKSPACE_USER,
    DEFAULT_WORKSPACE_USER_HOME,
    DEFAULT_WORKSPACE_USER_UID,
)

import tomllib

# TOML template scaffolded by `credproxy create`.
# Required: image (defaulted). Everything else is optional / commented out.
CONFIG_TEMPLATE = """\
# credproxy workspace config.
# Edit this file, then run `credproxy workspace {name} start` to apply.

# Workspace image. Changing this (or mounts/env/setup) recreates the
# workspace container on the next `start`.
image = "{image}"

# Where the persistent home volume mounts inside the workspace. Point this at
# the `user` below so their home is the persistent volume (the default image
# pre-creates /home/vscode owned by vscode, so it seeds correctly -- no chown).
{home_line}

# User that `enter` runs as (docker exec -u). The user must exist in the
# image -- built in (the default image ships `vscode`, uid 1000, with
# passwordless sudo), or created by `setup` (which always runs as root, so it
# can `useradd` + chown the home volume). Exec-only: changing it never
# recreates the container, and `enter --user NAME` overrides it per session.
{user_line}

# Make the non-root `user` above own your bind mounts, without changing
# ownership on the host. credproxy picks the runtime-appropriate lever:
# --userns=keep-id on rootless podman; on Docker the matching uid does it
# (the default `vscode` is uid 1000; on a custom image create the user as
# $CREDPROXY_HOST_UID in `setup`). Requires `user`. Recreates the container on
# change. A --userns in run_flags overrides this (run_flags is the escape hatch
# and wins), so you can hand-tune the mapping without unsetting it.
{map_line}

# The in-container uid of `user` -- the side map_host_user's keep-id maps your
# host uid onto, so it's what `user` must be for the mapping to line up. Host
# uid and this need not be equal. Defaults to your host uid (right for a user
# made as $CREDPROXY_HOST_UID in `setup`); set it to a baked user's uid (the
# default image's `vscode` is 1000). Recreates the container on change.
{user_uid_line}

# Command `enter` runs when you don't pass `-- CMD` (argv list). Defaults to a
# login shell, `["bash", "-l"]` -- entering the workspace is like logging in, so
# you get the full login environment. `enter -- CMD` still runs a bare command.
# shell = ["zsh"]

# Directory `enter` starts in (the workspaceFolder analog). Defaults to `home`,
# so you land in your home dir rather than the image's WORKDIR; point it at a
# bind-mounted project to land there instead. Exec-only -- no recreate.
# workdir = "/code"

# `enter` env shim. By default credproxy wraps the enter command in
# `sh -c '<prelude>; exec "$@"'`, sourcing the proxy's CA-env file so HTTPS-CA
# env vars reach an interactive shell, `enter -- cmd`, AND subprocesses (docker
# exec is a bare execve -- no shell init). Override the snippet here, or set it
# to "" to skip wrapping entirely (direct execve). Exec-only -- no recreate.
# enter_prelude = ". /etc/profile.d/credproxy.sh 2>/dev/null"

# Escape hatch: extra flags spliced into `docker exec` for `enter`
# (e.g. a working dir or env). credproxy keeps control of -i/-t/-d. Exec-only.
# exec_flags = ["--workdir", "/srv"]

# Escape hatch: extra flags spliced into the workspace `docker run`. Unlike
# exec_flags these shape the container, so changing them recreates it on the
# next `start`. credproxy's --name/labels/--network/home volume win on conflict.
# Useful for runtime-specific uid mapping so a non-root `user` can write bind
# mounts without changing host ownership, e.g. on rootless podman:
# run_flags = ["--userns=keep-id:uid=1000,gid=1000"]

# Host paths bind-mounted into the workspace. Each entry is
# "SRC:DST" or "SRC:DST:ro"; ~ is expanded on SRC.
# mounts = [
#   "~/code:/code",
# ]

# Extra environment variables injected into the workspace container.
# env = {{ GH_DEBUG = "1" }}

{setup_block}

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

    # workdir: directory `enter` starts in (docker exec --workdir), defaulting to
    # `home` at exec time. The workspaceFolder analog -- so `enter` lands in your
    # project (or home) rather than the image's WORKDIR. Exec-only (it's where
    # the exec starts, not a container change), so NOT part of the spec hash; a
    # --workdir in `exec_flags` still overrides it (docker last-wins).
    workdir = raw.get("workdir")
    if workdir is not None and (not isinstance(workdir, str) or not workdir.startswith("/")):
        raise ConfigError(f"{ws.config_path}: `workdir` must be an absolute path")

    # enter_prelude: escape hatch over the `enter` env shim. By default credproxy
    # wraps the enter command in `sh -c '<prelude>; exec "$@"'`, where the prelude
    # sources the proxy's CA-env file -- so the env reaches an interactive shell,
    # `enter -- cmd`, and subprocesses alike (docker exec is a bare execve). This
    # overrides that snippet; set it to "" to skip wrapping (direct execve).
    # Exec-only -> not part of the spec hash.
    enter_prelude = raw.get("enter_prelude")
    if enter_prelude is not None and not isinstance(enter_prelude, str):
        raise ConfigError(f"{ws.config_path}: `enter_prelude` must be a string")

    # shell: the command `enter` runs when no `-- CMD` is given (argv list).
    # Defaults to a LOGIN shell (`["bash", "-l"]`) -- semantically `enter` is
    # "log into the workspace" (the ssh model), so the interactive entry sources
    # the full login environment; `enter -- CMD` stays a bare, non-login command
    # (the ssh `host cmd` model). Exec-only -> not part of the spec hash.
    shell = raw.get("shell")
    if shell is not None and (
        not isinstance(shell, list) or not shell
        or not all(isinstance(s, str) and s for s in shell)
    ):
        raise ConfigError(
            f"{ws.config_path}: `shell` must be a non-empty array of non-empty strings"
        )

    # run_flags: escape hatch -- extra flags spliced into the workspace
    # `docker run` (e.g. ["--userns=keep-id:uid=1000,gid=1000"] for rootless
    # podman, or a custom idmapped mount). Unlike `exec_flags`, these shape the
    # container itself, so they ARE part of the spec hash: changing them
    # recreates the container on the next `start`. credproxy's structural flags
    # (--name, labels, --network, the home volume) are applied AFTER these and
    # win on conflict, so run_flags can't detach the netns or rename the box.
    run_flags = raw.get("run_flags") or []
    if not isinstance(run_flags, list) or not all(isinstance(f, str) for f in run_flags):
        raise ConfigError(f"{ws.config_path}: `run_flags` must be an array of strings")

    # map_host_user: let credproxy make the non-root `user` own the bind mounts
    # without changing host ownership, picking the runtime-appropriate lever
    # (--userns=keep-id on rootless podman; a no-op on Docker, where the matching
    # uid via CREDPROXY_HOST_UID handles it). Shapes the container -> part of the
    # spec hash. Requires a non-root `user` (validated below).
    map_host_user = raw.get("map_host_user", False)
    if not isinstance(map_host_user, bool):
        raise ConfigError(f"{ws.config_path}: `map_host_user` must be a boolean")

    # user_uid: the in-container uid of `user`. map_host_user's keep-id maps
    # host-you onto THIS uid, so it's the side the host must land on for `user`
    # to own the bind mounts (host uid and this need not be equal). Defaults to
    # the host uid (correct for a `setup`-provisioned user made as
    # $CREDPROXY_HOST_UID); set it to a baked user's uid (the default image's
    # `vscode` is 1000). Shapes the container -> part of the spec hash.
    user_uid = raw.get("user_uid")
    if user_uid is not None and (not isinstance(user_uid, int) or isinstance(user_uid, bool)
                                 or user_uid < 0):
        raise ConfigError(f"{ws.config_path}: `user_uid` must be a non-negative integer")

    # map_host_user / user_uid configure how the non-root `user` owns bind
    # mounts, so they're meaningless without one. Reject rather than silently
    # no-op -- a uid (or mapping toggle) for a non-existent user is a config
    # error, not an in-progress state worth tolerating.
    if user is None:
        orphans = [name for name, present in
                   (("map_host_user", map_host_user), ("user_uid", user_uid is not None))
                   if present]
        if orphans:
            joined = " and ".join(f"`{o}`" for o in orphans)
            verb, subj = ("require", "they") if len(orphans) > 1 else ("requires", "it")
            raise ConfigError(
                f"{ws.config_path}: {joined} {verb} `user` to be set "
                f"({subj} configure{'' if len(orphans) > 1 else 's'} how the "
                f"non-root `user` owns bind mounts)"
            )

    return {
        "image": image,
        "home": home,
        "mounts": mounts,
        "env": env,
        "setup": setup,
        "user": user,
        "workdir": workdir,
        "enter_prelude": enter_prelude,
        "shell": shell,
        "exec_flags": exec_flags,
        "run_flags": run_flags,
        "map_host_user": map_host_user,
        "user_uid": user_uid,
    }


def declared_config(ws: Workspace) -> dict:
    """The container-side settings literally present in the TOML, before any
    defaults are applied -- the raw declaration, for `config --declared`.
    Excludes the `[[binding]]` array (shown by `binding list`). Raises
    ConfigError on a missing file or parse error."""
    if not ws.exists():
        raise ConfigError(f"workspace '{ws.name}' not found (no {ws.config_path})")
    try:
        raw = tomllib.loads(ws.config_path.read_text())
    except Exception as e:
        raise ConfigError(f"{ws.config_path}: TOML parse error: {e}") from e
    return {k: v for k, v in raw.items() if k != "binding"}


def quick_image(ws: Workspace) -> str:
    """Best-effort `image` read for `list`, without full validation."""
    try:
        raw = tomllib.loads(ws.config_path.read_text())
        return raw.get("image") or DEFAULT_WORKSPACE_IMAGE
    except Exception:
        return "?"


def workspace_spec_hash(cfg: dict, proxy_id: str | None) -> str:
    """Identity of the workspace container's launch spec. Changing the
    image, home, mounts, env, setup, run_flags, map_host_user, user_uid, or the
    proxy container (netns peer) yields a new hash, which `start` uses to decide
    whether to recreate."""
    spec = json.dumps(
        {
            "image": cfg["image"],
            "home": cfg["home"],
            "mounts": cfg["mounts"],
            "env": cfg["env"],
            "setup": cfg["setup"],
            "run_flags": cfg.get("run_flags") or [],
            "map_host_user": bool(cfg.get("map_host_user")),
            "user_uid": cfg.get("user_uid"),
            "proxy": proxy_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(spec.encode()).hexdigest()[:16]


def render_template(name: str, image: str) -> str:
    """Scaffold a workspace TOML. For the default image (a devcontainers base
    that ships the `vscode` sudo user) the user/home/map_host_user settings are
    written ACTIVE, so a fresh workspace lands in a non-root sudo shell that owns
    its bind mounts with no extra config. For a `--image` override the user is
    unknown, so those lines stay commented hints."""
    if image == DEFAULT_WORKSPACE_IMAGE:
        home_line = f'home = "{DEFAULT_WORKSPACE_USER_HOME}"'
        user_line = f'user = "{DEFAULT_WORKSPACE_USER}"'
        map_line = "map_host_user = true"
        user_uid_line = f"user_uid = {DEFAULT_WORKSPACE_USER_UID}"
        # The default image has curl + update-ca-certificates, so the proxy CA
        # can be installed automatically -- HTTPS interception works right after
        # `enter`, no manual bootstrap. Runs as root on each (re)create.
        setup_block = (
            "# Commands run as root on each (re)created container; make them\n"
            "# idempotent. The default installs the proxy CA so HTTPS interception\n"
            '# works immediately; add your own (e.g. "npm ci") to the list.\n'
            "setup = [\n"
            '  "curl -fsSL http://proxy.local/bootstrap.sh | sh",\n'
            "]"
        )
    else:
        home_line = '# home = "/root"'
        user_line = '# user = "dev"'
        map_line = "# map_host_user = true"
        user_uid_line = "# user_uid = 1000"
        # Unknown image: leave setup commented. If it has curl +
        # update-ca-certificates, add the CA bootstrap so interception works.
        setup_block = (
            "# Commands run as root on each (re)created container; make them\n"
            "# idempotent. A failing command stops start and leaves the container\n"
            "# for debugging. On an image with curl + update-ca-certificates, add\n"
            '# the proxy-CA bootstrap so HTTPS interception works:\n'
            '#   "curl -fsSL http://proxy.local/bootstrap.sh | sh"\n'
            "# setup = [\n"
            '#   "npm ci",\n'
            "# ]"
        )
    return CONFIG_TEMPLATE.format(
        name=name, image=image, home_line=home_line, user_line=user_line,
        map_line=map_line, user_uid_line=user_uid_line, setup_block=setup_block,
    )
