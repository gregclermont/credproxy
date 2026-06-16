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
from .paths import DEFAULT_HOME, resolve_singleton
from .workspace import Workspace

import tomllib



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

    # image (mandatory -- the scaffold writes a concrete one; there is no
    # built-in default image to fall back to).
    image = raw.get("image")
    if not isinstance(image, str) or not image:
        raise ConfigError(
            f"{ws.config_path}: `image` is required (a non-empty string) -- "
            f"`credproxy workspace create` writes one for you"
        )

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
        return raw.get("image") or "?"
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


def render_template(name: str) -> str:
    """Scaffold a workspace TOML from the resolved template (the profile overlay's
    if present, else the builtin default). The template is a literal workspace
    config -- its image, user, home, and setup are concrete values; only `{name}`
    is substituted. To use a different image, edit the scaffolded file (the
    template's comments show what to adjust), or override the template in a
    profile overlay (see docs/forking.md)."""
    path = resolve_singleton("workspace.template.toml")
    if path is None:
        raise ConfigError(
            "no workspace.template.toml found (looked in the profile overlay "
            "and builtin defaults)"
        )
    return path.read_text().format(name=name)
