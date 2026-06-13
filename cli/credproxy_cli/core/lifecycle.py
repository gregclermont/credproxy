"""Workspace lifecycle: create files, run/start/stop/recreate containers.

Progress that the old monolith printed from inside these helpers is now
surfaced via an optional `notify: Callable[[str], None]`. Porcelain wires
it to stderr rendering (the `[credproxy] ` prefix); when omitted, progress
is silently dropped. The core never imports porcelain and never prints.

Setup commands (config key `setup`) run once after the workspace container
is (re)created. They do NOT re-run on a plain `start` of an existing
container. The spec hash that last successfully ran setup is recorded in
<state_dir>/setup_done; if the running container's spec hash matches that
file the setup phase is skipped.

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
import subprocess
from dataclasses import dataclass
from typing import Callable

from . import docker
from .config import (
    load_config,
    render_template,
    workspace_spec_hash,
)
from .errors import DockerError, ImageError, WorkspaceError
from .imageenv import ImageEnv
from .workspace import Workspace, ensure_token
from .paths import (
    DEFAULT_WORKSPACE_IMAGE,
    IMAGE_TAG,
    PROXY_DIR,
)
from .proxy_http import push_config, wait_for_ready

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


def create_ws_container(
    ws: Workspace, cfg: dict, spec_hash: str, proxy_id: str | None = None
) -> None:
    args = [
        "run", "-d",
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
    # env vars from config
    for k, v in cfg.get("env", {}).items():
        args += ["-e", f"{k}={v}"]
    # `tail -f /dev/null` keeps the container alive to `exec` into; the
    # image's own CMD is irrelevant to a credproxy workspace. `tail` is
    # used over `sleep infinity` because it works on busybox/alpine too.
    args += [cfg["image"], "tail", "-f", "/dev/null"]
    docker.docker(args)
    # Record the applied spec for itemizable drift.
    _write_applied_spec(ws, cfg, proxy_id)


def run_setup(ws: Workspace, cfg: dict, spec_hash: str, notify: Notify) -> None:
    """Run setup commands in the workspace container (once per spec hash).

    Checks <state_dir>/setup_done. If it contains the current spec_hash,
    setup is skipped. After all commands succeed, writes spec_hash to
    setup_done. A failing command raises DockerError and leaves the file
    unchanged (so the next `start` re-attempts setup)."""
    setup = cfg.get("setup") or []
    if not setup:
        return

    # Check if setup already ran for this spec.
    done_path = ws.setup_done_path
    if done_path.exists():
        recorded = done_path.read_text().strip()
        if recorded == spec_hash:
            return  # already done for this spec

    notify(f"running {len(setup)} setup command(s)...")
    for i, cmd in enumerate(setup):
        notify(f"  setup[{i}]: {cmd}")
        r = subprocess.run(
            ["docker", "exec", ws.ws_container, "sh", "-lc", cmd],
            check=False,
        )
        if r.returncode != 0:
            raise DockerError(
                f"setup command failed (exit {r.returncode}): {cmd!r}\n"
                f"The workspace container is left running for debugging."
            )

    # Record success.
    ws.ensure_state_dir()
    done_path.write_text(spec_hash + "\n")


def stop_workspace(ws: Workspace) -> None:
    """Stop the workspace, then the proxy (the workspace shares the
    proxy's netns). Best-effort -- absent containers are fine. A short
    timeout: PID 1 in both containers ignores SIGTERM, so the default
    10s grace would just delay the SIGKILL."""
    docker.docker_quiet(["stop", "-t", "1", ws.ws_container])
    docker.docker_quiet(["stop", "-t", "1", ws.proxy_container])


def start_workspace(ws: Workspace, notify: Notify = _noop) -> None:
    """Idempotently bring the workspace to fully-running. Auto-creates
    the workspace files if missing. Multiple workspaces run independently;
    other running workspaces are left untouched.

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
    elif status != "running":
        docker.docker(["start", ws.proxy_container])

    # Resolve the ephemeral host port assigned to this workspace's proxy.
    host_port = docker.resolve_host_port(ws.proxy_container, meta.http_port)
    wait_for_ready(host_port)

    # Always re-push: the proxy's tmpfs config does not survive a
    # `docker start`, and re-pushing also picks up config file edits.
    notify("pushing config...")
    pushed_bindings = push_config(ws, host_port, notify)
    if pushed_bindings is not None:
        _write_applied_bindings(ws, pushed_bindings)

    # ---- workspace container ----
    proxy_id = docker.inspect(ws.proxy_container, "{{.Id}}")
    spec_hash = workspace_spec_hash(cfg, proxy_id)
    status = docker.container_status(ws.ws_container)
    is_new_container = False
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
        is_new_container = True
    elif status != "running":
        docker.docker(["start", ws.ws_container])

    # ---- setup (once per spec hash, only on a freshly created container) ----
    if is_new_container:
        run_setup(ws, cfg, spec_hash, notify)


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


def enter_workspace(ws: Workspace, cmd: list[str], notify: Notify = _noop) -> int:
    """Start the workspace (if not running), run `cmd` inside it, and handle
    auto-stop when the session ends.

    Returns the exit code of the command.

    Session tracking: writes a pidfile to <state_dir>/sessions/<pid> before
    running. This uses subprocess.run (not os.execvp) so we can clean up and
    check auto-stop after the command exits.

    TTY forwarding: -t is passed when sys.stdin is a TTY. -i is always passed
    so stdin is wired even in non-interactive use (consistent with the old
    os.execvp path).

    Signal handling: subprocess.run propagates SIGINT to the subprocess via
    the normal terminal signal delivery; we do NOT set up SIGINT forwarding
    explicitly since docker exec in the same process group receives it.
    """
    import os
    import sys

    start_workspace(ws, notify)

    # Build the docker exec command.
    exec_cmd = ["docker", "exec", "-i"]
    if sys.stdin.isatty():
        exec_cmd.append("-t")
    exec_cmd.append(ws.ws_container)
    exec_cmd += cmd

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
