"""Workspace lifecycle: create files, run/start/stop/recreate containers.

Progress that the old monolith printed from inside these helpers is now
surfaced via an optional `notify: Callable[[str], None]`. Porcelain wires
it to stderr rendering (the `[credproxy] ` prefix); when omitted, progress
is silently dropped. The core never imports porcelain and never prints.

Setup commands (config key `setup`) run once per container instance: on a
freshly created/recreated container, and on the next `start` after a failed
attempt (the <state_dir>/setup_done marker records the container id that
COMPLETED setup, written only on success -- so a failure retries). A plain
`start`/`stop` of an existing container does NOT re-run them (same id, writable
layer intact). Because a recreate re-runs them, setup commands should be
idempotent.

Applied-state records (written by this module, no side effects on read):
  <state_dir>/applied-spec.json   — the spec dict that fed the last
      successful workspace container creation (image, home, mounts, env,
      setup, proxy_id). Used by inspect/apply for itemizable drift.
  <state_dir>/applied-bindings.json — binding metadata (name, injector,
      provider, secret, hosts, placeholder, env) pushed to the proxy after
      a successful config push. NO secret values. Used by inspect/apply.
"""
from __future__ import annotations

import json
import os
import posixpath
import subprocess
from dataclasses import dataclass
from typing import Callable

from . import docker
from .config import (
    load_config,
    render_template,
    workspace_spec_hash,
)
from .errors import DockerError, ImageError, ProxyError, WorkspaceError
from .imageenv import ImageEnv
from .workspace import Workspace, ensure_token
from .paths import (
    DEFAULT_WORKSPACE_IMAGE,
    IMAGE_TAG,
    PROXY_DIR,
)
from .proxy_http import proxy_status, push_config, wait_for_ready

Notify = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


# ---- applied-state helpers --------------------------------------------------


def _write_applied_spec(ws: Workspace, cfg: dict, proxy_id: str | None) -> None:
    """Write the workspace launch spec to <state_dir>/applied-spec.json.

    Called after creating the workspace container. The spec matches what
    workspace_spec_hash() hashes, so drift can be recomputed exactly."""
    ws.ensure_state_dir()
    spec = {
        "image": cfg["image"],
        "home": cfg["home"],
        "mounts": cfg["mounts"],
        "env": cfg["env"],
        "setup": cfg["setup"],
        "run_flags": cfg.get("run_flags") or [],
        "map_host_user": bool(cfg.get("map_host_user")),
        "user_uid": cfg.get("user_uid"),
        "proxy_id": proxy_id,
    }
    ws.applied_spec_path.write_text(json.dumps(spec, indent=2) + "\n")


def _write_applied_bindings(ws: Workspace, bindings) -> None:
    """Write binding metadata (no secret values) to applied-bindings.json.

    `bindings` is a list of Binding dataclass instances (from bindings.py).
    Only structural metadata is recorded; `real` secret values are never
    written here."""
    ws.ensure_state_dir()
    records = [
        {
            "name": b.name,
            "injector": b.injector,
            "provider": b.provider,
            "secret": b.secret,
            "hosts": list(b.hosts),
            "placeholder": b.placeholder,
            "env": b.env,
        }
        for b in bindings
    ]
    ws.applied_bindings_path.write_text(json.dumps(records, indent=2) + "\n")


def _load_applied_spec(ws: Workspace) -> dict | None:
    """Load the last recorded applied spec. Returns None if not present."""
    if not ws.applied_spec_path.exists():
        return None
    try:
        return json.loads(ws.applied_spec_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _load_applied_bindings(ws: Workspace) -> list[dict] | None:
    """Load the last recorded applied bindings. Returns None if not present."""
    if not ws.applied_bindings_path.exists():
        return None
    try:
        return json.loads(ws.applied_bindings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def create_workspace_files(ws: Workspace, image: str) -> None:
    if ws.exists():
        raise WorkspaceError(
            f"workspace '{ws.name}' already exists ({ws.config_path})"
        )
    ws.config_path.parent.mkdir(parents=True, exist_ok=True)
    ws.config_path.write_text(render_template(ws.name, image))
    ensure_token(ws)


def create_proxy(ws: Workspace, meta: ImageEnv) -> None:
    args = [
        "run", "-d",
        "--name", ws.proxy_container,
        "--label", "credproxy.role=proxy",
        "--label", f"credproxy.workspace={ws.name}",
        "--cap-add", "NET_ADMIN",
        # The workspace's own name, exposed to the workspace via /setup (e.g.
        # to customize the shell prompt). Not a secret -- it is the instance's
        # handle. Set at create; inherited by the proxy process and persists
        # across `docker start` / `dev reload`.
        "-e", f"CREDPROXY_WORKSPACE={ws.name}",
        # mode=1777 so the proxy's unprivileged uid can write config.json:
        # the tmpfs dir's default mode is not writable by it, and Docker
        # mounts it differently on `docker run` vs. a later `docker start`.
        "--tmpfs", f"{meta.tmpfs}:size=64k,mode=1777",
        # Bind the host token in read-only. The `:Z` SELinux relabel (private)
        # is required on enforcing-SELinux hosts (Fedora/RHEL) so the proxy can
        # read it -- without it the file keeps its host label and the container
        # is denied. `:Z` is a no-op on non-SELinux hosts and accepted by both
        # Docker and Podman; `-v` (not `--mount`) is used because Docker rejects
        # `relabel=` on `--mount`. The proxy stays SELinux-confined (it is the
        # privileged, secret-holding component); only the workspace disables it.
        "-v", f"{ws.token_path}:{meta.token}:ro,Z",
        # Ephemeral host port: the runtime assigns a free port per proxy
        # container so multiple workspaces run simultaneously without port
        # conflicts. The empty host-port spelling (`ip::container`) means
        # "pick a random port" on both Docker and Podman; Docker also accepts
        # `:0:` but Podman does not, so use `::` for cross-runtime support.
        "-p", f"127.0.0.1::{meta.http_port}",
    ]
    # Dev convenience: bind-mount the proxy source so `dev reload` picks
    # up edits. Skipped if run outside the repo checkout. `:z` (shared SELinux
    # relabel) so the proxy can read it under enforcing SELinux; no-op without.
    if PROXY_DIR.is_dir():
        args += ["-v", f"{PROXY_DIR}:{meta.source}:z"]
    args.append(IMAGE_TAG)
    docker.docker(args)


def _credproxy_owns_user_mapping(cfg: dict) -> bool:
    """True when credproxy owns this workspace's uid mapping: `map_host_user` is
    set and the workspace runs as a non-root `user`.

    The precondition for both levers that assume host-you maps onto the container
    user -- the `--userns=keep-id` flag (rootless podman) and the mount-parent
    chown (every runtime). Outside this mode credproxy must not presume the
    mapped uid is the right owner: a root workspace already owns everything, and
    a user-supplied `run_flags` namespace is theirs to map."""
    user = cfg.get("user")
    return bool(cfg.get("map_host_user") and user and user not in ("root", "0"))


def _mapped_uid(cfg: dict) -> int:
    """The workspace user's in-container uid -- the uid host-you maps onto under
    `map_host_user`, so the owner that keep-id targets AND the mount-parent chown
    must use. `user_uid` if set (a baked user like vscode=1000), else the host
    uid (a user provisioned as $CREDPROXY_HOST_UID in `setup`). Callers guard
    `hasattr(os, "getuid")` before relying on the fallback."""
    uid = cfg.get("user_uid")
    return os.getuid() if uid is None else uid


def _host_user_run_flags(cfg: dict) -> list[str]:
    """The userns flag that makes a non-root `user` own the bind mounts when
    `map_host_user` is set -- runtime-specific, host ownership untouched.

    Only rootless podman needs a lever: there the userns maps host-you to
    container-root, so a non-root user can't write the mounts; --userns=keep-id
    maps your host uid/gid onto the workspace user instead. On Docker (uids 1:1)
    and when map_host_user is off this is a no-op. Returns [] unless the runtime
    actually needs it, so the same config stays portable across runtimes.

    The keep-id `uid` is the workspace user's IN-CONTAINER uid -- that's the side
    of the map host-you must land on for the user to own the mounts. It comes
    from `user_uid` if set (e.g. the default image's `vscode` is uid 1000),
    otherwise it falls back to the host uid (correct for a user provisioned in
    `setup` as $CREDPROXY_HOST_UID). host uid and the user's uid may differ
    freely -- keep-id maps across them; they need not be equal.

    A no-op without credproxy-owned mapping: the default root workspace already
    owns the mounts on every runtime, so there is nothing to map (and we skip the
    runtime probe). Checked before the probe so the common root workspace pays no
    daemon round-trip."""
    if not _credproxy_owns_user_mapping(cfg) or not hasattr(os, "getuid"):
        return []
    from .runtime import is_podman_rootless
    if not is_podman_rootless():
        return []
    return [f"--userns=keep-id:uid={_mapped_uid(cfg)},gid={os.getgid()}"]


def _mount_parent_dirs(cfg: dict) -> list[str]:
    """Directories the container runtime fabricates (as container-root) for bind
    targets nested under `home` -- the intermediate path components between the
    home volume and each mount point.

    Derived from cfg["mounts"], the same list that produced the --mount flags, so
    it matches exactly what the runtime created -- no in-container mountinfo scan.
    A target one level under home (its parent IS the home volume) fabricates
    nothing and is correctly owned; only deeper nesting yields work. Targets
    outside home live in the ephemeral container layer and are skipped: inside the
    credproxy-managed home volume the chown is provably host-safe."""
    home = cfg["home"].rstrip("/")
    dirs: set[str] = set()
    for m in cfg["mounts"]:
        target = m["target"].rstrip("/")
        if not target.startswith(home + "/"):
            continue
        d = posixpath.dirname(target)
        while d != home and d != "/":
            dirs.add(d)
            d = posixpath.dirname(d)
    return sorted(dirs)


def chown_mount_parents(ws: Workspace, cfg: dict, notify: Notify) -> None:
    """Re-own the runtime-fabricated parents of nested bind mounts to the
    workspace user, so `map_host_user`'s promise (the non-root user owns the
    mounts) holds for the dirs the runtime invented as container-root too.

    Gated on credproxy owning the uid mapping; the chown target is the mapped uid
    (`user_uid`/host uid -- the same uid keep-id uses, so the parents land on the
    user that runs inside). Runtime-agnostic, unlike the keep-id flag: the
    fabricated parent is container-root on rootless podman AND rootful Docker
    (uid 0 is host root), so a non-root user is locked out on both. Non-recursive
    -- chowns only the intermediate dirs, never a mount point, so host files are
    untouched. Idempotent (everything under the home volume should be user-owned
    anyway), so re-chowning pre-existing ancestors is a harmless no-op."""
    if not _credproxy_owns_user_mapping(cfg) or not hasattr(os, "getuid"):
        return
    parents = _mount_parent_dirs(cfg)
    if not parents:
        return
    notify(f"fixing ownership of {len(parents)} mount parent dir(s)...")
    docker.docker(["exec", "-u", "0", ws.ws_container,
                   "chown", f"{_mapped_uid(cfg)}:{os.getgid()}", *parents])


def create_ws_container(
    ws: Workspace, cfg: dict, spec_hash: str, proxy_id: str | None = None
) -> None:
    args = [
        "run", "-d",
        # credproxy-managed userns mapping (map_host_user) goes FIRST, so a
        # user-supplied --userns in run_flags below overrides it (docker
        # last-wins). run_flags is the escape hatch and beats the convenience
        # knob -- mirroring how exec_flags overrides config user/workdir on
        # `enter`. Safe to let run_flags win here because the user namespace is
        # orthogonal to the shared netns (--network container:..., below).
        *_host_user_run_flags(cfg),
        # Escape hatch: after keep-id (so it can override it) but BEFORE
        # credproxy's structural flags below (--name, labels, --network, home
        # volume), which are applied last and win on conflict -- so a stray
        # --network/--name in run_flags still can't detach the netns or rename
        # the box. Additive flags (extra --mount/-v, --security-opt) just apply.
        *(cfg.get("run_flags") or []),
        "--name", ws.ws_container,
        "--label", "credproxy.role=workspace",
        "--label", f"credproxy.workspace={ws.name}",
        "--label", f"credproxy.spec={spec_hash}",
        # Run the workspace with SELinux labeling disabled (like distrobox /
        # toolbx). On enforcing-SELinux hosts this lets the user's bind mounts
        # be read WITHOUT relabeling -- i.e. without mutating the SELinux
        # context of the user's own project directories. It is a no-op on
        # non-SELinux hosts. The tradeoff is that the workspace container loses
        # SELinux confinement; acceptable because the workspace runs the user's
        # own workload (credproxy is a credential boundary, not a hardened
        # jail) and the privileged proxy stays confined.
        "--security-opt", "label=disable",
        # Share the proxy's netns so all egress is captured.
        "--network", f"container:{ws.proxy_container}",
        # Persistent home volume; seeded from the image's home on first run.
        "-v", f"{ws.home_volume}:{cfg['home']}",
    ]
    for m in cfg["mounts"]:
        opt = f"type=bind,source={m['source']},target={m['target']}"
        if m["readonly"]:
            opt += ",readonly"
        args += ["--mount", opt]
    # Self-config breadcrumb: a tenant (e.g. an agent) that inspects its
    # environment finds the inward setup surface proactively, without first
    # having to trip a TLS-interception error and investigate it. Points at the
    # agent-facing guidance; /etc/hosts already resolves proxy.local.
    args += ["-e", "CREDPROXY_SETUP=http://proxy.local/llms.txt"]
    # The workspace's own name, also available via /setup. Handy for setup
    # scripts and shell rc (e.g. a prompt label) that would otherwise template
    # the literal name. Stable per workspace, so (like CREDPROXY_SETUP) it's not
    # part of the spec hash -- an existing container picks it up on next recreate.
    args += ["-e", f"CREDPROXY_WORKSPACE={ws.name}"]
    # Host identity breadcrumb: the uid/gid the CLI runs as -- i.e. the owner of
    # the user's bind-mounted project dirs. `setup` can match a non-root user to
    # it (`useradd -u $CREDPROXY_HOST_UID dev`) so that user can read/write the
    # mounts without changing host ownership; the same value feeds a rootless
    # podman `run_flags = ["--userns=keep-id:uid=$CREDPROXY_HOST_UID"]`. Stable
    # per host user, so (like CREDPROXY_SETUP) it's not part of the spec hash.
    host_uid = getattr(os, "getuid", lambda: None)()
    host_gid = getattr(os, "getgid", lambda: None)()
    if host_uid is not None:
        args += ["-e", f"CREDPROXY_HOST_UID={host_uid}",
                 "-e", f"CREDPROXY_HOST_GID={host_gid}"]
    # env vars from config (after the breadcrumbs, so a user could override them)
    for k, v in cfg.get("env", {}).items():
        args += ["-e", f"{k}={v}"]
    # `tail -f /dev/null` keeps the container alive to `exec` into; the
    # image's own CMD is irrelevant to a credproxy workspace. `tail` is
    # used over `sleep infinity` because it works on busybox/alpine too.
    args += [cfg["image"], "tail", "-f", "/dev/null"]
    docker.docker(args)
    # Record the applied spec for itemizable drift.
    _write_applied_spec(ws, cfg, proxy_id)


def _read_setup_marker(ws: Workspace) -> str | None:
    """The container id that last COMPLETED setup, or None."""
    p = ws.setup_done_path
    return p.read_text().strip() if p.exists() else None


def _write_setup_marker(ws: Workspace, container_id: str) -> None:
    ws.ensure_state_dir()
    ws.setup_done_path.write_text(container_id + "\n")


def _setup_needed(marker: str | None, container_id: str) -> bool:
    """Setup is needed when this container hasn't recorded a completed run: a
    new/recreated container (different id), or one where a prior attempt failed
    (no marker written). A plain stop/start keeps the id, so setup is skipped."""
    return bool(container_id) and marker != container_id


def run_setup(ws: Workspace, cfg: dict, notify: Notify) -> None:
    """Run the `setup` commands in the workspace container, as root (`-u 0`) via
    `docker exec`. Called from start_workspace when the container hasn't recorded
    a completed setup (see `_setup_needed`): a fresh container, or a prior
    attempt that failed. A failing command raises DockerError and leaves the
    container running for debugging -- and, since the success marker isn't
    written, the next `start` retries setup.

    Root is pinned with `-u 0` rather than inherited from the image default,
    because the container's default run-user is not always root: `map_host_user`
    adds `--userns=keep-id`, under which podman runs the container as the mapped
    (non-root) uid, and a user could bake `USER dev` into their image. setup is
    the place to provision (useradd, apt, chown the home volume), so it must be
    root regardless; uid 0 is root-in-namespace even under keep-id (where it maps
    to a subuid). `enter` pins its own `-u <user>`, so the two never collide.

    Setup commands should be idempotent: a container recreate (spec drift or a
    manual `docker rm`) re-runs them, while the persistent home volume
    survives -- so writable-layer work (apt, useradd) is re-provisioned and
    home-volume work just needs to be cheap to repeat."""
    setup = cfg.get("setup") or []
    if not setup:
        return
    notify(f"running {len(setup)} setup command(s)...")
    for i, cmd in enumerate(setup):
        notify(f"  setup[{i}]: {cmd}")
        r = subprocess.run(
            ["docker", "exec", "-u", "0", ws.ws_container, "sh", "-lc", cmd],
            check=False,
        )
        if r.returncode != 0:
            raise DockerError(
                f"setup command failed (exit {r.returncode}): {cmd!r}\n"
                f"The workspace container is left running for debugging."
            )


def stop_workspace(ws: Workspace) -> None:
    """Stop the workspace, then the proxy (the workspace shares the
    proxy's netns). Best-effort -- absent containers are fine. A short
    timeout: PID 1 in both containers ignores SIGTERM, so the default
    10s grace would just delay the SIGKILL."""
    docker.docker_quiet(["stop", "-t", "1", ws.ws_container])
    docker.docker_quiet(["stop", "-t", "1", ws.proxy_container])


def _proxy_diagnostics(ws: Workspace) -> str:
    """Explain why the proxy isn't answering /health, by inspecting its
    container. The common case is a crash on boot (the container has exited);
    surface its exit code and recent log tail so the failure is actionable
    without a second command."""
    status = docker.container_status(ws.proxy_container)
    if status is None:
        return f"  (the proxy container {ws.proxy_container} is gone)"
    if status == "exited":
        code = docker.inspect(ws.proxy_container, "{{.State.ExitCode}}") or "?"
        head = f"  the proxy container exited (code {code}) -- it crashed on startup."
    else:
        head = f"  the proxy container is '{status}' but not answering /health."
    lines = [head]
    tail = [ln for ln in docker.logs_tail(ws.proxy_container, 20).splitlines() if ln.strip()]
    if tail:
        lines.append("  last proxy log lines:")
        lines += [f"    {ln}" for ln in tail[-12:]]
    lines.append(f"  full logs: credproxy workspace {ws.name} logs")
    return "\n".join(lines)


def _should_push(force_push: bool, proxy_fresh: bool,
                 status: dict | None, want_fp: str) -> bool:
    """Decide whether to (re)push config. Push when forced (`enter --push`,
    `start`), when the proxy was just (re)started (its tmpfs config is empty),
    or when we can't confirm it already holds the intended config -- it is
    unreachable/unknown (None), reports no config, or reports a different
    fingerprint. Only a confirmed matching fingerprint skips the push."""
    if force_push or proxy_fresh:
        return True
    if not status or not status.get("loaded"):
        return True
    return status.get("fingerprint") != want_fp


def start_workspace(ws: Workspace, notify: Notify = _noop,
                    force_push: bool = True) -> None:
    """Idempotently bring the workspace to fully-running. Auto-creates
    the workspace files if missing. Multiple workspaces run independently;
    other running workspaces are left untouched.

    `force_push` (default True for explicit `start`) always re-pushes config;
    `enter` passes force_push=False for a fast path that skips the push -- and
    the provider calls it implies -- when the already-running proxy reports the
    intended config's fingerprint.

    Progress is reported through `notify`."""
    if not ws.exists():
        create_workspace_files(ws, DEFAULT_WORKSPACE_IMAGE)
        notify(f"created workspace '{ws.name}'")

    meta = ImageEnv.load()
    cfg = load_config(ws)

    ensure_token(ws)

    # ---- proxy ----
    image_id = docker.inspect(IMAGE_TAG, "{{.Id}}")
    if image_id is None:
        raise ImageError(
            f"image {IMAGE_TAG} not found; run `credproxy dev build` first"
        )

    proxy_fresh = False  # created or started this call -> tmpfs config is empty
    status = docker.container_status(ws.proxy_container)
    if status is not None and \
            docker.inspect(ws.proxy_container, "{{.Image}}") != image_id:
        notify("proxy image changed; recreating proxy "
               "(workspace will need re-bootstrap)")
        docker.docker_quiet(["rm", "-f", ws.proxy_container])
        status = None
    if status is None:
        notify("starting proxy...")
        create_proxy(ws, meta)
        proxy_fresh = True
    elif status != "running":
        docker.docker(["start", ws.proxy_container])
        proxy_fresh = True

    # Resolve the ephemeral host port assigned to this workspace's proxy.
    host_port = docker.resolve_host_port(ws.proxy_container, meta.http_port)
    try:
        wait_for_ready(host_port)
    except ProxyError as e:
        # The bare readiness error ("Connection refused") hides the usual
        # cause: the proxy crashed on boot. Surface its exit + log tail inline
        # so the user doesn't have to run `logs` separately to find out.
        raise ProxyError(f"{e}\n{_proxy_diagnostics(ws)}") from e

    # Push the bindings config -- but on the `enter` fast path, skip it (and the
    # provider calls it implies) when the already-running proxy reports the
    # intended config's fingerprint. The proxy's tmpfs config does not survive a
    # restart, so a (re)started proxy (proxy_fresh) always gets a push.
    from .bindings import config_fingerprint, materialize_bindings
    bindings = materialize_bindings(ws, notify)
    want_fp = config_fingerprint(bindings)
    status = None if (force_push or proxy_fresh) else proxy_status(ws, host_port)
    if _should_push(force_push, proxy_fresh, status, want_fp):
        notify("pushing config...")
        pushed_bindings = push_config(ws, host_port, notify,
                                      bindings=bindings, fingerprint=want_fp)
        if pushed_bindings is not None:
            _write_applied_bindings(ws, pushed_bindings)
    else:
        notify("config unchanged on the proxy; skipped push "
               "(use `enter --push` to refresh)")

    # ---- workspace container ----
    proxy_id = docker.inspect(ws.proxy_container, "{{.Id}}")
    spec_hash = workspace_spec_hash(cfg, proxy_id)
    status = docker.container_status(ws.ws_container)
    if status is not None:
        current = docker.inspect(
            ws.ws_container, '{{index .Config.Labels "credproxy.spec"}}'
        )
        if current != spec_hash:
            notify("workspace spec changed; recreating workspace container")
            docker.docker_quiet(["rm", "-f", ws.ws_container])
            status = None
    if status is None:
        notify("starting workspace container...")
        create_ws_container(ws, cfg, spec_hash, proxy_id=proxy_id)
    elif status != "running":
        docker.docker(["start", ws.ws_container])

    # ---- setup (once per container instance; retries a failed prior attempt) ----
    # Gate on the container id: a freshly created/recreated container has a new
    # id (-> run), a plain stop/start keeps the same id (-> skip), and the marker
    # is written only AFTER setup succeeds -- so a failed setup re-runs on the
    # next `start`.
    container_id = docker.inspect(ws.ws_container, "{{.Id}}")
    if _setup_needed(_read_setup_marker(ws), container_id):
        # Before setup, since a setup command's user phase may write into a
        # nested mount's parent (e.g. clone a sibling repo under ~/src). Same
        # cadence as setup: runs once per fresh/recreated container (the
        # fabricated parents live in the home volume, so idempotent thereafter).
        chown_mount_parents(ws, cfg, notify)
        run_setup(ws, cfg, notify)
        _write_setup_marker(ws, container_id)


def delete_workspace(ws: Workspace) -> None:
    """Remove both containers, the home volume, the config file, and
    the state dir. Best-effort on the Docker objects (absent ones are fine)."""
    import shutil

    docker.docker_quiet(["rm", "-f", ws.ws_container])
    docker.docker_quiet(["rm", "-f", ws.proxy_container])
    docker.docker_quiet(["volume", "rm", ws.home_volume])
    # Remove config file
    if ws.config_path.exists():
        ws.config_path.unlink()
    # Remove state dir
    shutil.rmtree(ws.state_dir, ignore_errors=True)


@dataclass(frozen=True)
class BindingSummary:
    name: str
    injector: str
    provider: str
    secret: str | dict[str, str]
    hosts: tuple[str, ...]
    placeholder: str | None
    env: str | None


@dataclass(frozen=True)
class DriftItem:
    """One detected difference between configured and applied state."""
    kind: str        # "container" or "bindings"
    item: str        # e.g. "image", "binding added: 'x'"
    applied: object  # value in applied state
    configured: object  # value in configured state


@dataclass(frozen=True)
class DriftReport:
    in_sync: bool
    changes: tuple[DriftItem, ...]


@dataclass(frozen=True)
class WorkspaceInspect:
    """A point-in-time view of a workspace: its config path, parsed config,
    container statuses, resolved host port (if running), binding summary,
    and a drift report comparing configured vs applied state."""

    name: str
    config_path: str
    config: dict          # normalized container-side settings (load_config)
    proxy_status: str | None    # docker status or None if absent
    ws_status: str | None
    running: bool
    host_port: int | None       # resolved proxy host port when running
    bindings: tuple[BindingSummary, ...]
    drift: DriftReport


def _compute_drift(
    ws: Workspace,
    cfg: dict,
    current_bindings: list,   # list of BindingSummary-like (name, injector, provider, secret, hosts, placeholder, env)
    running: bool,
) -> DriftReport:
    """Compare current config against the last applied spec + bindings.

    Container-spec drift is compared against applied-spec.json.
    Bindings drift is compared against applied-bindings.json.
    Returns a DriftReport with all detected changes."""
    changes: list[DriftItem] = []

    applied_spec = _load_applied_spec(ws)
    applied_bindings = _load_applied_bindings(ws)

    # ---- container-spec drift ----
    if applied_spec is None:
        # No record; can't compute drift -- treated as in sync for container
        # (the "never started" case is indicated by running=False + no record).
        pass
    else:
        # Compare fields that feed the spec hash.
        for field in ("image", "home", "env", "setup"):
            configured_val = cfg[field]
            applied_val = applied_spec.get(field)
            if configured_val != applied_val:
                changes.append(DriftItem(
                    kind="container",
                    item=field,
                    applied=applied_val,
                    configured=configured_val,
                ))
        # mounts: compare list of dicts
        configured_mounts = cfg["mounts"]
        applied_mounts = applied_spec.get("mounts") or []
        if configured_mounts != applied_mounts:
            changes.append(DriftItem(
                kind="container",
                item="mounts",
                applied=applied_mounts,
                configured=configured_mounts,
            ))
        # run_flags: list of strings (missing in pre-run_flags specs -> [])
        configured_run_flags = cfg.get("run_flags") or []
        applied_run_flags = applied_spec.get("run_flags") or []
        if configured_run_flags != applied_run_flags:
            changes.append(DriftItem(
                kind="container",
                item="run_flags",
                applied=applied_run_flags,
                configured=configured_run_flags,
            ))
        # map_host_user: bool (missing in older specs -> False)
        configured_map = bool(cfg.get("map_host_user"))
        applied_map = bool(applied_spec.get("map_host_user"))
        if configured_map != applied_map:
            changes.append(DriftItem(
                kind="container",
                item="map_host_user",
                applied=applied_map,
                configured=configured_map,
            ))
        # user_uid: optional int (missing in older specs -> None)
        if cfg.get("user_uid") != applied_spec.get("user_uid"):
            changes.append(DriftItem(
                kind="container",
                item="user_uid",
                applied=applied_spec.get("user_uid"),
                configured=cfg.get("user_uid"),
            ))

    # ---- bindings drift ----
    if applied_bindings is None:
        # No record; skip bindings drift.
        pass
    else:
        # Build lookup dicts keyed by binding name.
        applied_by_name = {b["name"]: b for b in applied_bindings}
        configured_by_name = {b.name: b for b in current_bindings}

        # Bindings added in config but not in applied.
        for name in configured_by_name:
            if name not in applied_by_name:
                changes.append(DriftItem(
                    kind="bindings",
                    item=f"binding added: '{name}'",
                    applied=None,
                    configured=_binding_summary_dict(configured_by_name[name]),
                ))

        # Bindings removed from config but still in applied.
        for name in applied_by_name:
            if name not in configured_by_name:
                changes.append(DriftItem(
                    kind="bindings",
                    item=f"binding removed: '{name}'",
                    applied=applied_by_name[name],
                    configured=None,
                ))

        # Bindings present in both: check for changes.
        for name in configured_by_name:
            if name not in applied_by_name:
                continue
            cb = configured_by_name[name]
            ab = applied_by_name[name]
            diffs = []
            for field in ("injector", "provider", "secret", "placeholder", "env"):
                cv = getattr(cb, field, None) if hasattr(cb, field) else cb.get(field)
                av = ab.get(field)
                if cv != av:
                    diffs.append(f"{field}: {av!r} -> {cv!r}")
            # hosts: compare as sorted lists for order-independent comparison
            cb_hosts = sorted(cb.hosts) if hasattr(cb, "hosts") else sorted(cb.get("hosts", []))
            ab_hosts = sorted(ab.get("hosts", []))
            if cb_hosts != ab_hosts:
                diffs.append(f"hosts: {ab_hosts!r} -> {cb_hosts!r}")
            if diffs:
                changes.append(DriftItem(
                    kind="bindings",
                    item=f"binding changed: '{name}' ({', '.join(diffs)})",
                    applied=ab,
                    configured=_binding_summary_dict(cb),
                ))

    return DriftReport(in_sync=len(changes) == 0, changes=tuple(changes))


def _binding_summary_dict(b) -> dict:
    """Convert a BindingSummary (or dict) to a plain dict for DriftItem."""
    if isinstance(b, dict):
        return b
    return {
        "name": b.name,
        "injector": b.injector,
        "provider": b.provider,
        "secret": b.secret,
        "hosts": list(b.hosts),
        "placeholder": b.placeholder,
        "env": b.env,
    }


def inspect_workspace(ws: Workspace) -> WorkspaceInspect:
    """Gather config + running state + a binding summary + drift report for `ws`.

    Reads bindings WITHOUT fetching secrets or materializing the file (so
    inspect is side-effect-free); a yet-unmaterialized name/placeholder shows
    as its auto-derived name / None placeholder."""
    from .bindings import _parse_bindings, _with_auto_names
    import tomllib

    if not ws.exists():
        raise WorkspaceError(f"workspace '{ws.name}' not found")

    cfg = load_config(ws)

    proxy_status = docker.container_status(ws.proxy_container)
    ws_status = docker.container_status(ws.ws_container)
    running = ws_status == "running"

    host_port: int | None = None
    if proxy_status == "running":
        try:
            meta = ImageEnv.load()
            host_port = docker.resolve_host_port(ws.proxy_container, meta.http_port)
        except (ImageError, DockerError):
            host_port = None

    raw = tomllib.loads(ws.config_path.read_text())
    parsed = _with_auto_names(_parse_bindings(raw, str(ws.config_path)))
    bindings = tuple(
        BindingSummary(
            name=b.name,
            injector=b.injector,
            provider=b.provider,
            secret=b.secret,
            hosts=b.hosts,
            placeholder=b.placeholder,
            env=b.env,
        )
        for b in parsed
    )

    drift = _compute_drift(ws, cfg, bindings, running)

    return WorkspaceInspect(
        name=ws.name,
        config_path=str(ws.config_path),
        config=cfg,
        proxy_status=proxy_status,
        ws_status=ws_status,
        running=running,
        host_port=host_port,
        bindings=bindings,
        drift=drift,
    )


@dataclass(frozen=True)
class ApplyResult:
    """Structured result of an `apply` operation.

    applied:  list of item labels that were live-applied (e.g. "bindings (x, y)")
    deferred: list of item labels that cannot be live-applied (e.g. "image")
              with a restart hint embedded in the label.
    """
    applied: tuple[str, ...]
    deferred: tuple[str, ...]


def apply_config(ws: Workspace, notify: Notify = _noop) -> ApplyResult:
    """Best-effort reconcile: apply what can be applied live; defer the rest.

    - Bindings drift → re-resolve + push to the running proxy. Reports
      "applied: bindings (...)". Updates applied-bindings.json on success.
    - Container-spec drift (image/home/mounts/env/setup) → CANNOT be applied
      live; reported as "deferred: <field> (restart to apply: ...)".
    - Nothing drifted → both lists empty.
    - Workspace not running → raises WorkspaceError.

    Returns ApplyResult; never raises on deferred items (exit 0 is the contract).
    """
    from .bindings import _parse_bindings, _with_auto_names
    import tomllib

    if docker.container_status(ws.proxy_container) != "running":
        raise WorkspaceError(
            f"workspace '{ws.name}' is not running; "
            f"start it first (`credproxy workspace {ws.name} start`)"
        )

    cfg = load_config(ws)
    meta = ImageEnv.load()
    host_port = docker.resolve_host_port(ws.proxy_container, meta.http_port)

    # Read current configured bindings (in-memory names only, no push yet).
    raw = tomllib.loads(ws.config_path.read_text())
    current_bindings_parsed = _with_auto_names(
        _parse_bindings(raw, str(ws.config_path))
    )

    # Build the binding summaries for drift.
    current_binding_summaries = [
        BindingSummary(
            name=b.name,
            injector=b.injector,
            provider=b.provider,
            secret=b.secret,
            hosts=b.hosts,
            placeholder=b.placeholder,
            env=b.env,
        )
        for b in current_bindings_parsed
    ]

    drift = _compute_drift(ws, cfg, current_binding_summaries, running=True)

    applied_labels: list[str] = []
    deferred_labels: list[str] = []

    # Container-spec items can't be applied live.
    container_changes = [c for c in drift.changes if c.kind == "container"]
    for change in container_changes:
        deferred_labels.append(
            f"{change.item} (restart to apply: "
            f"credproxy workspace {ws.name} start)"
        )

    # Bindings drift -> push.
    bindings_changes = [c for c in drift.changes if c.kind == "bindings"]
    if bindings_changes:
        binding_items = [c.item for c in bindings_changes]
        pushed_bindings = push_config(ws, host_port, notify)
        if pushed_bindings is not None:
            _write_applied_bindings(ws, pushed_bindings)
        applied_labels.append(f"bindings ({', '.join(binding_items)})")
    elif not container_changes:
        # No drift at all.
        pass

    return ApplyResult(
        applied=tuple(applied_labels),
        deferred=tuple(deferred_labels),
    )


def reload_proxy(ws: Workspace) -> None:
    """SIGHUP the workspace's proxy so python re-execs in place. Raises
    WorkspaceError if the proxy is not running."""
    if docker.container_status(ws.proxy_container) != "running":
        raise WorkspaceError(f"proxy for workspace '{ws.name}' is not running")
    docker.docker(["kill", "--signal=HUP", ws.proxy_container])


# ---- auto-stop / session tracking -------------------------------------------


def _session_pidfile(ws: Workspace, pid: int) -> "Path":
    from pathlib import Path
    return ws.sessions_dir / str(pid)


def _clean_stale_sessions(ws: Workspace) -> None:
    """Remove pidfiles for processes that are no longer alive."""
    if not ws.sessions_dir.exists():
        return
    import os
    for pidfile in ws.sessions_dir.iterdir():
        try:
            pid = int(pidfile.name)
        except ValueError:
            pidfile.unlink(missing_ok=True)
            continue
        try:
            os.kill(pid, 0)  # liveness check
        except ProcessLookupError:
            pidfile.unlink(missing_ok=True)
        except PermissionError:
            pass  # process exists but owned by another user; leave it


def _count_live_sessions(ws: Workspace, exclude_pid: int | None = None) -> int:
    """Count live (other than exclude_pid) sessions for the workspace."""
    if not ws.sessions_dir.exists():
        return 0
    import os
    count = 0
    for pidfile in ws.sessions_dir.iterdir():
        try:
            pid = int(pidfile.name)
        except ValueError:
            continue
        if pid == exclude_pid:
            continue
        try:
            os.kill(pid, 0)
            count += 1
        except (ProcessLookupError, PermissionError):
            pass
    return count


def _enter_exec_cmd(cfg: dict, container: str, cmd: list[str], *,
                    user_override: str | None, isatty: bool) -> list[str]:
    """Assemble the `docker exec` argv for `enter`.

    Ordering exploits docker's last-wins flag parsing to keep credproxy in
    control of session behaviour while still honouring `user` + the `exec_flags`
    escape hatch: the default `--workdir` (config `workdir`, else `home`), then
    config `user`, then `exec_flags` (may override -w/-u or add -e), then the
    per-session `user_override`, then credproxy's session-control flags as
    EXPLICIT booleans last -- so a stray -d/-t/-i in `exec_flags` can't detach
    the session or break pidfile/auto-stop tracking, and a -w there still wins."""
    out = ["docker", "exec"]
    # Land in `workdir` (the workspaceFolder analog), defaulting to `home`, so
    # enter drops you in your project/home rather than the image's WORKDIR.
    # Emitted before exec_flags so a --workdir there still wins (docker last-wins).
    workdir = cfg.get("workdir") or cfg.get("home")
    if workdir:
        out += ["--workdir", workdir]
    if cfg.get("user") and not user_override:
        out += ["-u", cfg["user"]]
    out += cfg.get("exec_flags") or []
    if user_override:
        out += ["-u", user_override]
    out += ["--interactive=true", f"--tty={'true' if isatty else 'false'}", "--detach=false"]
    out.append(container)
    if not cmd:
        # No explicit `-- CMD`: run the config `shell`, defaulting to a login
        # shell. `enter` is "log into the workspace" (ssh model), so the
        # interactive entry sources the full login env; an explicit command
        # stays bare/non-login (the ssh `host cmd` model).
        cmd = list(cfg.get("shell") or DEFAULT_ENTER_CMD)
    out += _enter_command(cfg, cmd)
    return out


# Default `enter` command when none is given and no `shell` is configured: a
# LOGIN shell, so interactive entry behaves like logging into the box.
DEFAULT_ENTER_CMD = ["bash", "-l"]


# Default `enter` env shim: source the proxy's bootstrap-written env file (CA
# bundle vars) before exec'ing the command. Guarded by `[ -f ... ]` so a missing
# file (bootstrap not run yet) is a no-op, not an error that would abort before
# the exec.
DEFAULT_ENTER_PRELUDE = (
    "[ -f /etc/profile.d/credproxy.sh ] && . /etc/profile.d/credproxy.sh"
)


def _enter_command(cfg: dict, cmd: list[str]) -> list[str]:
    """The command argv for `enter`, optionally wrapped in an env shim.

    By default credproxy wraps the command in `sh -c '<prelude>; exec "$@"'`,
    where the prelude sources the proxy's bootstrap-written env file
    (/etc/profile.d/credproxy.sh -- the CA-bundle vars). This is the only way to
    get that env into BOTH an interactive shell AND `enter -- cmd` AND their
    subprocesses: docker exec is a direct execve (no shell init, no PAM), so the
    env file otherwise loads only in a login shell. `exec "$@"` replaces the shim
    in place, so there's no extra PID and signals/TTY/exit code/argv all pass
    through; `$0` is a label shown in error messages.

    Escape hatch: `enter_prelude` overrides the shell snippet; set it to "" to
    skip wrapping entirely (direct execve, no /bin/sh dependency)."""
    prelude = cfg.get("enter_prelude")
    if prelude is None:
        prelude = DEFAULT_ENTER_PRELUDE
    if not prelude:
        return list(cmd)
    return ["sh", "-c", f'{prelude}; exec "$@"', "credproxy-enter", *cmd]


def effective_config(cfg: dict) -> dict:
    """A copy of the parsed config with the *enter-time* defaults resolved, for
    display (`config`/`inspect`).

    load_config already fills the create-time defaults (image, home, empty
    mounts/env/setup, map_host_user). This additionally resolves the two fields
    whose defaults are computed at enter time, so they don't show as null when
    they actually have an effect: `workdir` -> `home`, and `enter_prelude` ->
    the default shim snippet. The result reflects what `enter` actually does."""
    out = dict(cfg)
    out["workdir"] = cfg.get("workdir") or cfg.get("home")
    ep = cfg.get("enter_prelude")
    out["enter_prelude"] = DEFAULT_ENTER_PRELUDE if ep is None else ep
    out["shell"] = list(cfg.get("shell") or DEFAULT_ENTER_CMD)
    # user_uid defaults to the host uid (the keep-id target when unset)
    uid = cfg.get("user_uid")
    if uid is None and hasattr(os, "getuid"):
        uid = os.getuid()
    out["user_uid"] = uid
    return out


def enter_workspace(ws: Workspace, cmd: list[str], notify: Notify = _noop,
                    user_override: str | None = None, push: bool = False) -> int:
    """Start the workspace (if not running), run `cmd` inside it, and handle
    auto-stop when the session ends.

    Returns the exit code of the command.

    Session tracking: writes a pidfile to <state_dir>/sessions/<pid> before
    running. This uses subprocess.run (not os.execvp) so we can clean up and
    check auto-stop after the command exits.

    User: the config `user` runs the exec as that user (`docker exec -u`);
    `user_override` (from `enter --user`) beats it for one session. The escape
    hatch `exec_flags` is spliced in too. Ordering exploits docker's last-wins
    parsing: config user, then exec_flags (may override -u or add -w/-e), then
    the override, then credproxy's session-control flags as EXPLICIT booleans
    last -- so a stray -d/-t/-i in exec_flags can't break session tracking.

    Signal handling: subprocess.run propagates SIGINT to the subprocess via
    the normal terminal signal delivery; we do NOT set up SIGINT forwarding
    explicitly since docker exec in the same process group receives it.
    """
    import os
    import sys

    start_workspace(ws, notify, force_push=push)
    cfg = load_config(ws)

    exec_cmd = _enter_exec_cmd(
        cfg, ws.ws_container, cmd,
        user_override=user_override, isatty=sys.stdin.isatty(),
    )

    # Register session pidfile.
    pid = os.getpid()
    ws.sessions_dir.mkdir(parents=True, exist_ok=True)
    pidfile = _session_pidfile(ws, pid)
    pidfile.write_text(str(pid))

    try:
        result = subprocess.run(exec_cmd, check=False)
        exit_code = result.returncode
    finally:
        # Always clean up our pidfile.
        pidfile.unlink(missing_ok=True)

    # Auto-stop: read config fresh (live config edit semantics).
    _maybe_auto_stop(ws, pid, notify)

    return exit_code


def _maybe_auto_stop(ws: Workspace, our_pid: int, notify: Notify) -> None:
    """Stop the workspace if auto_stop is enabled and no other sessions live."""
    import tomllib

    # Read config fresh -- auto_stop may have been edited mid-session.
    if not ws.config_path.exists():
        return
    try:
        raw = tomllib.loads(ws.config_path.read_text())
    except Exception:
        return
    if not raw.get("auto_stop", False):
        return

    # Clean up stale pidfiles; then check for other live sessions.
    _clean_stale_sessions(ws)
    other_sessions = _count_live_sessions(ws, exclude_pid=our_pid)
    if other_sessions > 0:
        return  # other sessions still alive; don't stop

    notify(f"auto_stop: stopping workspace '{ws.name}'")
    stop_workspace(ws)
