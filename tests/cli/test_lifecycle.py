"""Tests for core/lifecycle.py: _compute_drift itemization, apply
applied/deferred partitioning (stubbed push), and auto-stop session counting."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ---- helpers -----------------------------------------------------------------


def _write_ws(workspaces_dir: Path, name: str, content: str = 'image = "x"\n'):
    from credproxy_cli.core.workspace import Workspace
    p = workspaces_dir / f"{name}.toml"
    p.write_text(content)
    return Workspace(name)


def _write_applied_spec(ws, image="x", home="/root", mounts=None, env=None,
                        setup=None, proxy_id=None):
    """Write a fake applied-spec.json for drift testing."""
    ws.ensure_state_dir()
    spec = {
        "image": image,
        "home": home,
        "mounts": mounts or [],
        "env": env or {},
        "setup": setup or [],
        "proxy_id": proxy_id,
    }
    ws.applied_spec_path.write_text(json.dumps(spec))


def _write_applied_bindings(ws, bindings: list):
    """Write a fake applied-bindings.json for drift testing."""
    ws.ensure_state_dir()
    ws.applied_bindings_path.write_text(json.dumps(bindings))


def _make_binding_summary(name="b", injector="github", provider="env",
                           secret="X", hosts=("api.github.com",),
                           placeholder="ph", env=None):
    from credproxy_cli.core.lifecycle import BindingSummary
    return BindingSummary(
        name=name, injector=injector, provider=provider,
        secret=secret, hosts=hosts, placeholder=placeholder, env=env,
    )


# ---- SELinux mount flags (cross-runtime: no-op without SELinux) --------------


def _capture_docker_args(monkeypatch):
    """Stub lifecycle.docker.docker to record the args of each run."""
    calls = []
    monkeypatch.setattr("credproxy_cli.core.lifecycle.docker.docker",
                        lambda args, **kw: calls.append(args))
    return calls


def test_proxy_relabels_its_own_mounts(xdg, ws_factory, monkeypatch):
    """The proxy stays SELinux-confined: its token mount is relabeled private
    (:Z) so it can read it under enforcing SELinux, converted from --mount to
    -v (Docker rejects relabel= on --mount). It must NOT disable labeling."""
    from credproxy_cli.core import lifecycle
    from credproxy_cli.core.imageenv import ImageEnv
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    meta = ImageEnv(http_port=39998, tmpfs="/run/secrets",
                    token="/run/secrets-ro/auth.token", source="/opt/proxy")
    lifecycle.create_proxy(ws, meta)
    joined = " ".join(calls[-1])
    assert f"{ws.token_path}:/run/secrets-ro/auth.token:ro,Z" in joined
    assert "--mount" not in calls[-1]       # token converted from --mount to -v
    assert "label=disable" not in joined    # proxy stays confined


def test_workspace_disables_selinux_labeling(xdg, ws_factory, monkeypatch):
    """The workspace runs with label=disable so user bind mounts work without
    relabeling (mutating) the user's own directories."""
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    assert "--security-opt" in args
    assert args[args.index("--security-opt") + 1] == "label=disable"


# ---- _compute_drift: no applied record = in sync ----------------------------


def test_drift_no_applied_record(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d1")
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=False)
    assert report.in_sync is True
    assert report.changes == ()


# ---- _compute_drift: container-spec drift ------------------------------------


def test_drift_image_changed(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d2", 'image = "new_image"\n')
    ws.ensure_state_dir()
    _write_applied_spec(ws, image="old_image")

    cfg = {"image": "new_image", "home": "/root", "mounts": [], "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    items = {c.item for c in report.changes}
    assert "image" in items
    c = next(c for c in report.changes if c.item == "image")
    assert c.kind == "container"
    assert c.applied == "old_image"
    assert c.configured == "new_image"


def test_drift_env_added(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d3")
    _write_applied_spec(ws, env={})

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {"NEW": "1"}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    items = {c.item for c in report.changes}
    assert "env" in items


def test_drift_setup_changed(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d4")
    _write_applied_spec(ws, setup=["old cmd"])

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": ["new cmd"]}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    items = {c.item for c in report.changes}
    assert "setup" in items


def test_drift_mounts_changed(xdg, workspaces_dir, tmp_path):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d5")
    _write_applied_spec(ws, mounts=[])

    src = tmp_path / "code"
    src.mkdir()
    new_mounts = [{"source": str(src), "target": "/code", "readonly": False}]
    cfg = {"image": "x", "home": "/root", "mounts": new_mounts, "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    items = {c.item for c in report.changes}
    assert "mounts" in items


def test_drift_in_sync(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "d6")
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [])

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)

    assert report.in_sync is True
    assert report.changes == ()


# ---- _compute_drift: bindings drift ------------------------------------------


def test_drift_binding_added(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "bd1")
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [])  # none applied

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    current_bindings = [_make_binding_summary("newb")]
    report = _compute_drift(ws, cfg, current_bindings, running=True)

    assert not report.in_sync
    items = [c.item for c in report.changes]
    assert any("binding added" in it and "newb" in it for it in items)


def test_drift_binding_removed(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "bd2")
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [{
        "name": "oldb", "injector": "github", "provider": "env",
        "secret": "X", "hosts": ["h.io"], "placeholder": "ph", "env": None,
    }])

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    items = [c.item for c in report.changes]
    assert any("binding removed" in it and "oldb" in it for it in items)


def test_drift_binding_changed(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "bd3")
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [{
        "name": "myb", "injector": "github", "provider": "env",
        "secret": "old_secret", "hosts": ["h.io"], "placeholder": "ph", "env": None,
    }])

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    current = [_make_binding_summary("myb", secret="new_secret", hosts=("h.io",))]
    report = _compute_drift(ws, cfg, current, running=True)

    assert not report.in_sync
    items = [c.item for c in report.changes]
    assert any("binding changed" in it and "myb" in it for it in items)


def test_drift_binding_hosts_order_insensitive(xdg, workspaces_dir):
    """Host order should not create false drift."""
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "bd4")
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [{
        "name": "myb", "injector": "github", "provider": "env",
        "secret": "X", "hosts": ["b.io", "a.io"], "placeholder": "ph", "env": None,
    }])

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    current = [_make_binding_summary("myb", hosts=("a.io", "b.io"))]
    report = _compute_drift(ws, cfg, current, running=True)

    # Only binding changes if any, not due to host order
    binding_changes = [c for c in report.changes if "binding changed" in c.item]
    assert len(binding_changes) == 0


# ---- apply_config: applied/deferred partitioning ----------------------------


def test_apply_container_drift_is_deferred(xdg, workspaces_dir, monkeypatch):
    """Container-spec drift goes to deferred, not applied."""
    from credproxy_cli.core.lifecycle import apply_config

    ws = _write_ws(workspaces_dir, "app1", 'image = "new_image"\n')
    ws.ensure_state_dir()
    _write_applied_spec(ws, image="old_image")
    _write_applied_bindings(ws, [])

    # Stub docker and push so we don't need real containers.
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.docker.container_status",
        lambda name: "running",
    )
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.docker.resolve_host_port",
        lambda container, port: 39998,
    )
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.ImageEnv.load",
        classmethod(lambda cls: type("FakeEnv", (), {
            "http_port": 39998, "tmpfs": "/run/secrets",
            "token": "/run/secrets-ro/auth.token", "source": "/opt/proxy",
        })()),
    )
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.push_config",
        lambda ws, port, notify=None: None,
    )

    result = apply_config(ws)
    assert any("image" in d for d in result.deferred)
    assert result.applied == ()


def test_apply_bindings_drift_is_applied(xdg, workspaces_dir, monkeypatch):
    """Bindings drift triggers a push and goes to applied."""
    from credproxy_cli.core.lifecycle import apply_config, BindingSummary
    from credproxy_cli.core.bindings import Binding

    ws = _write_ws(workspaces_dir, "app2", """\
image = "x"

[[binding]]
name = "myb"
injector = "github"
provider = "env"
secret = "TOK"
hosts = ["api.github.com"]
placeholder = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
""")
    ws.ensure_state_dir()
    _write_applied_spec(ws)
    _write_applied_bindings(ws, [])  # binding not yet applied

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.docker.container_status",
        lambda name: "running",
    )
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.docker.resolve_host_port",
        lambda container, port: 39998,
    )
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.ImageEnv.load",
        classmethod(lambda cls: type("FakeEnv", (), {
            "http_port": 39998, "tmpfs": "/run/secrets",
            "token": "/run/secrets-ro/auth.token", "source": "/opt/proxy",
        })()),
    )

    pushed = []

    def fake_push(ws, port, notify=None):
        pushed.append(True)
        return [Binding(
            name="myb", injector="github", provider="env",
            secret="TOK", hosts=("api.github.com",),
            placeholder="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            env="GITHUB_TOKEN",
        )]

    monkeypatch.setattr("credproxy_cli.core.lifecycle.push_config", fake_push)

    result = apply_config(ws)
    assert len(pushed) == 1
    assert any("bindings" in a for a in result.applied)
    assert result.deferred == ()


def test_apply_not_running_raises(xdg, workspaces_dir, monkeypatch):
    from credproxy_cli.core.errors import WorkspaceError
    from credproxy_cli.core.lifecycle import apply_config

    ws = _write_ws(workspaces_dir, "app3")
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.docker.container_status",
        lambda name: None,
    )

    with pytest.raises(WorkspaceError, match="not running"):
        apply_config(ws)


# ---- auto-stop: session counting ---------------------------------------------


def _make_session(ws, pid: int) -> None:
    """Write a fake pidfile for `pid`."""
    ws.sessions_dir.mkdir(parents=True, exist_ok=True)
    (ws.sessions_dir / str(pid)).write_text(str(pid))


def test_count_live_sessions_empty(xdg, workspaces_dir):
    from credproxy_cli.core.lifecycle import _count_live_sessions

    ws = _write_ws(workspaces_dir, "s1")
    assert _count_live_sessions(ws) == 0


def test_count_live_sessions_current_process(xdg, workspaces_dir):
    """Current process's pidfile counts as a live session."""
    from credproxy_cli.core.lifecycle import _count_live_sessions

    ws = _write_ws(workspaces_dir, "s2")
    pid = os.getpid()
    _make_session(ws, pid)
    assert _count_live_sessions(ws) >= 1


def test_count_live_sessions_exclude_pid(xdg, workspaces_dir):
    """exclude_pid omits our own session from the count."""
    from credproxy_cli.core.lifecycle import _count_live_sessions

    ws = _write_ws(workspaces_dir, "s3")
    pid = os.getpid()
    _make_session(ws, pid)
    # Exclude self; should be 0 live sessions remaining
    assert _count_live_sessions(ws, exclude_pid=pid) == 0


def test_clean_stale_sessions(xdg, workspaces_dir):
    """Stale pidfiles (for non-existent PIDs) are removed."""
    from credproxy_cli.core.lifecycle import _clean_stale_sessions

    ws = _write_ws(workspaces_dir, "s4")
    # PID 1 is always alive; use a high unlikely PID for stale
    stale_pid = 9999999  # highly unlikely to exist
    _make_session(ws, stale_pid)

    _clean_stale_sessions(ws)

    # The stale pidfile should be gone (if pid really is dead)
    # We can only assert this if we know the pid is dead.
    try:
        os.kill(stale_pid, 0)
        # pid actually exists, skip assertion
    except ProcessLookupError:
        assert not (ws.sessions_dir / str(stale_pid)).exists()


def test_clean_stale_ignores_invalid_filename(xdg, workspaces_dir):
    """Non-numeric pidfiles are cleaned up without crashing."""
    from credproxy_cli.core.lifecycle import _clean_stale_sessions

    ws = _write_ws(workspaces_dir, "s5")
    ws.sessions_dir.mkdir(parents=True, exist_ok=True)
    (ws.sessions_dir / "notanumber").write_text("x")

    _clean_stale_sessions(ws)
    assert not (ws.sessions_dir / "notanumber").exists()


# ---- run_setup: runs on every (new) container, no per-spec skip --------------


def _fake_run(calls, code=0):
    class _R:
        returncode = code
    def run(cmd, **kw):
        calls.append(cmd)
        return _R()
    return run


def test_run_setup_runs_every_call(xdg, ws_factory, monkeypatch):
    """run_setup has no per-spec skip: invoked twice (as it would be on two
    successive fresh containers), it re-runs all commands both times."""
    from credproxy_cli.core import lifecycle
    calls = []
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_run(calls))
    ws = ws_factory("a")
    cfg = {"setup": ["echo one", "echo two"]}
    lifecycle.run_setup(ws, cfg, notify=lambda *_: None)
    lifecycle.run_setup(ws, cfg, notify=lambda *_: None)
    assert len(calls) == 4  # 2 commands x 2 invocations
    assert calls[0][:3] == ["docker", "exec", ws.ws_container]
    assert "echo one" in calls[0]


def test_run_setup_noop_without_commands(xdg, ws_factory, monkeypatch):
    from credproxy_cli.core import lifecycle
    calls = []
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_run(calls))
    lifecycle.run_setup(ws_factory("a"), {}, notify=lambda *_: None)
    assert calls == []


def test_run_setup_failure_raises(xdg, ws_factory, monkeypatch):
    from credproxy_cli.core import lifecycle
    from credproxy_cli.core.errors import DockerError
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_run([], code=7))
    with pytest.raises(DockerError):
        lifecycle.run_setup(ws_factory("a"), {"setup": ["false"]},
                            notify=lambda *_: None)
