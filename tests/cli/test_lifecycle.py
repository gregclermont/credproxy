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


def test_host_uid_gid_injected_into_workspace_env(xdg, ws_factory, monkeypatch):
    """The workspace gets CREDPROXY_HOST_UID/GID (= the CLI's uid/gid) so setup
    can match a non-root user to the bind-mount owner without host chowns."""
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    assert f"CREDPROXY_HOST_UID={os.getuid()}" in args
    assert f"CREDPROXY_HOST_GID={os.getgid()}" in args


def test_workspace_name_injected_into_workspace_env(xdg, ws_factory, monkeypatch):
    """The workspace gets CREDPROXY_WORKSPACE=<name> so setup scripts / shell rc
    can read the name (e.g. a prompt label) instead of templating the literal."""
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    assert f"CREDPROXY_WORKSPACE={ws.name}" in args


def test_config_env_overrides_host_uid_breadcrumb(xdg, ws_factory, monkeypatch):
    """A user's `env` is applied after the breadcrumbs, so it wins (last -e)."""
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {"CREDPROXY_HOST_UID": "999"},
           "setup": []}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    # the override comes after the breadcrumb in argv -> docker last-wins
    e_indices = [i for i, a in enumerate(args) if a == "CREDPROXY_HOST_UID=999"]
    assert e_indices and e_indices[-1] > args.index("-e")


def test_map_host_user_injects_keepid_on_podman_rootless(xdg, ws_factory, monkeypatch):
    """map_host_user + podman-rootless -> --userns=keep-id with the CLI's uid."""
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless", lambda: True)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "user": "dev", "map_host_user": True}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    flag = f"--userns=keep-id:uid={os.getuid()},gid={os.getgid()}"
    assert flag in args
    # credproxy-managed userns precedes --name/--network (stays authoritative)
    assert args.index(flag) < args.index("--name")


def test_map_host_user_keepid_targets_user_uid(xdg, ws_factory, monkeypatch):
    """keep-id's uid is the user's in-container uid (user_uid), NOT the host uid,
    so host uid != user uid lines up (e.g. vscode=1000 on a host with uid 501)."""
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless", lambda: True)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "user": "vscode", "map_host_user": True, "user_uid": 1000}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    assert f"--userns=keep-id:uid=1000,gid={os.getgid()}" in args


def test_run_flags_userns_overrides_map_host_user(xdg, ws_factory, monkeypatch):
    """A --userns in run_flags wins over map_host_user's keep-id (escape hatch
    beats the knob): run_flags is spliced AFTER keep-id, but both stay before
    the structural flags so the netns is still protected."""
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless", lambda: True)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    keepid = f"--userns=keep-id:uid={os.getuid()},gid={os.getgid()}"
    # A DISTINCT userns so it can never collide with the getuid-derived keep-id
    # above -- otherwise args.index() can't tell the two positions apart when the
    # runner's own uid matches a hardcoded value (e.g. uid 1000 inside a
    # credproxy workspace, where this suite would otherwise fail spuriously).
    override = f"--userns=keep-id:uid={os.getuid() + 1},gid={os.getgid() + 1}"
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "user": "vscode", "map_host_user": True,
           "run_flags": [override]}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    # both present; run_flags override comes AFTER keep-id (docker last-wins)
    assert args.index(override) > args.index(keepid)
    # ...but still before the structural flags (netns protected)
    assert args.index(override) < args.index("--network")


def test_map_host_user_noop_on_docker(xdg, ws_factory, monkeypatch):
    """map_host_user on a non-podman-rootless runtime injects nothing."""
    from credproxy_cli.core import lifecycle
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless", lambda: False)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "user": "dev", "map_host_user": True}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    assert not any(a.startswith("--userns") for a in calls[-1])


def _nested_cfg(**over):
    cfg = {"image": "x", "home": "/home/vscode",
           "mounts": [{"source": "/h/src/proj", "target": "/home/vscode/src/proj",
                       "readonly": False}],
           "env": {}, "setup": [], "user": "vscode", "map_host_user": True}
    cfg.update(over)
    return cfg


def test_mount_parent_dirs_nested_yields_intermediate(xdg):
    from credproxy_cli.core.lifecycle import _mount_parent_dirs
    assert _mount_parent_dirs(_nested_cfg()) == ["/home/vscode/src"]


def test_mount_parent_dirs_deep_nesting_yields_all_ancestors(xdg):
    from credproxy_cli.core.lifecycle import _mount_parent_dirs
    cfg = _nested_cfg(mounts=[{"source": "x", "target": "/home/vscode/a/b/proj",
                               "readonly": False}])
    assert _mount_parent_dirs(cfg) == ["/home/vscode/a", "/home/vscode/a/b"]


def test_mount_parent_dirs_one_level_under_home_is_empty(xdg):
    """A target whose parent IS the home volume fabricates nothing."""
    from credproxy_cli.core.lifecycle import _mount_parent_dirs
    cfg = _nested_cfg(mounts=[{"source": "x", "target": "/home/vscode/proj",
                               "readonly": False}])
    assert _mount_parent_dirs(cfg) == []


def test_mount_parent_dirs_outside_home_skipped(xdg):
    from credproxy_cli.core.lifecycle import _mount_parent_dirs
    cfg = _nested_cfg(mounts=[{"source": "x", "target": "/srv/a/proj",
                               "readonly": False}])
    assert _mount_parent_dirs(cfg) == []


def test_owns_user_mapping(xdg):
    from credproxy_cli.core.lifecycle import _credproxy_owns_user_mapping
    assert _credproxy_owns_user_mapping(_nested_cfg()) is True
    assert _credproxy_owns_user_mapping(_nested_cfg(map_host_user=False)) is False
    assert _credproxy_owns_user_mapping(_nested_cfg(user="root")) is False
    assert _credproxy_owns_user_mapping(_nested_cfg(user=None)) is False


def test_chown_mount_parents_uses_mapped_uid(xdg, ws_factory, monkeypatch):
    """The chown targets the MAPPED uid (user_uid), same as keep-id -- NOT the
    host uid, so the fabricated parent lands on the user that runs inside."""
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a"); ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    lifecycle.chown_mount_parents(ws, _nested_cfg(user_uid=1000), lambda *_: None)
    args = calls[-1]
    assert args[:4] == ["exec", "-u", "0", ws.ws_container]
    assert args[4:6] == ["chown", f"1000:{os.getgid()}"]   # user_uid, not os.getuid()
    assert args[-1] == "/home/vscode/src"


def test_chown_mount_parents_falls_back_to_host_uid(xdg, ws_factory, monkeypatch):
    import os
    if not hasattr(os, "getuid"):
        import pytest
        pytest.skip("no getuid on this platform")
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a"); ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    lifecycle.chown_mount_parents(ws, _nested_cfg(), lambda *_: None)  # no user_uid
    assert calls[-1][4:6] == ["chown", f"{os.getuid()}:{os.getgid()}"]


def test_chown_mount_parents_noop_without_mapping(xdg, ws_factory, monkeypatch):
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a"); ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    lifecycle.chown_mount_parents(ws, _nested_cfg(map_host_user=False), lambda *_: None)
    assert calls == []


def test_chown_mount_parents_noop_when_no_fabricated_parents(xdg, ws_factory, monkeypatch):
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a"); ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = _nested_cfg(mounts=[{"source": "x", "target": "/home/vscode/proj",
                               "readonly": False}])
    lifecycle.chown_mount_parents(ws, cfg, lambda *_: None)
    assert calls == []


def test_map_host_user_noop_without_user(xdg, ws_factory, monkeypatch):
    """map_host_user with no non-root `user` is a no-op (root already owns the
    mounts) and short-circuits before the runtime probe."""
    from credproxy_cli.core import lifecycle
    probed = []
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless",
                        lambda: probed.append(True) or True)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "map_host_user": True}  # no `user`
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    assert not any(a.startswith("--userns") for a in calls[-1])
    assert probed == []


def test_map_host_user_off_skips_probe_and_flag(xdg, ws_factory, monkeypatch):
    """With map_host_user off, no userns flag and the runtime probe isn't even
    consulted (no daemon round-trip on the common root workspace)."""
    from credproxy_cli.core import lifecycle
    probed = []
    monkeypatch.setattr("credproxy_cli.core.runtime.is_podman_rootless",
                        lambda: probed.append(True) or True)
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    assert not any(a.startswith("--userns") for a in calls[-1])
    assert probed == []  # short-circuited before the probe


def test_run_flags_spliced_before_structural_flags(xdg, ws_factory, monkeypatch):
    """run_flags are spliced into `docker run` ahead of credproxy's structural
    flags (--name, --network), so docker's last-wins parsing keeps credproxy in
    control of the netns and container name."""
    from credproxy_cli.core import lifecycle
    ws = ws_factory("a")
    ws.ensure_state_dir()
    calls = _capture_docker_args(monkeypatch)
    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "run_flags": ["--userns=keep-id:uid=1000,gid=1000"]}
    lifecycle.create_ws_container(ws, cfg, "deadbeef", proxy_id="pid")
    args = calls[-1]
    assert "--userns=keep-id:uid=1000,gid=1000" in args
    # escape-hatch flag precedes --name and --network (credproxy wins on conflict)
    assert args.index("--userns=keep-id:uid=1000,gid=1000") < args.index("--name")
    assert args.index("--userns=keep-id:uid=1000,gid=1000") < args.index("--network")


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


def test_drift_run_flags_changed(xdg, workspaces_dir):
    """Adding run_flags drifts against an applied spec that had none (the
    pre-run_flags spec normalizes a missing field to [], so this is also the
    backward-compat case)."""
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "drf")
    _write_applied_spec(ws)  # no run_flags key -> treated as []

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": [],
           "run_flags": ["--userns=keep-id"]}
    report = _compute_drift(ws, cfg, [], running=True)

    assert not report.in_sync
    c = next(c for c in report.changes if c.item == "run_flags")
    assert c.kind == "container"
    assert c.applied == []
    assert c.configured == ["--userns=keep-id"]


def test_drift_no_run_flags_is_in_sync(xdg, workspaces_dir):
    """A workspace with no run_flags and a pre-run_flags applied spec is in sync
    (no false-positive drift from the missing field)."""
    from credproxy_cli.core.lifecycle import _compute_drift

    ws = _write_ws(workspaces_dir, "drf2")
    _write_applied_spec(ws)  # no run_flags key

    cfg = {"image": "x", "home": "/root", "mounts": [], "env": {}, "setup": []}
    report = _compute_drift(ws, cfg, [], running=True)
    assert report.in_sync is True


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


def test_effective_config_resolves_enter_time_defaults(xdg):
    """effective_config fills the enter-time defaults so they aren't null:
    workdir -> home, enter_prelude -> the default shim snippet."""
    from credproxy_cli.core.lifecycle import effective_config, DEFAULT_ENTER_PRELUDE
    cfg = {"home": "/home/vscode", "workdir": None, "enter_prelude": None}
    eff = effective_config(cfg)
    assert eff["workdir"] == "/home/vscode"
    assert eff["enter_prelude"] == DEFAULT_ENTER_PRELUDE


def test_effective_config_preserves_explicit_values(xdg):
    """Explicit values win, including an explicit "" enter_prelude (shim off)."""
    from credproxy_cli.core.lifecycle import effective_config
    eff = effective_config({"home": "/home/vscode", "workdir": "/code", "enter_prelude": ""})
    assert eff["workdir"] == "/code"
    assert eff["enter_prelude"] == ""


def test_effective_config_resolves_shell(xdg):
    """shell -> the login-shell default when unset, explicit when set."""
    from credproxy_cli.core.lifecycle import effective_config, DEFAULT_ENTER_CMD
    assert effective_config({"home": "/h"})["shell"] == DEFAULT_ENTER_CMD
    assert effective_config({"home": "/h", "shell": ["zsh"]})["shell"] == ["zsh"]


def test_effective_config_resolves_user_uid(xdg):
    """user_uid -> the host uid (keep-id target) when unset, explicit when set."""
    import os
    from credproxy_cli.core.lifecycle import effective_config
    if hasattr(os, "getuid"):
        assert effective_config({"home": "/h"})["user_uid"] == os.getuid()
    assert effective_config({"home": "/h", "user_uid": 1000})["user_uid"] == 1000


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
    # setup is pinned to root (-u 0), not the container's default run-user
    # (which keep-id / a baked `USER` could make non-root).
    assert calls[0][:5] == ["docker", "exec", "-u", "0", ws.ws_container]
    assert "echo one" in calls[0]


def test_run_setup_pins_root(xdg, ws_factory, monkeypatch):
    """Every setup exec carries `-u 0` so provisioning is root regardless of the
    container's default user (keep-id under map_host_user, or a baked USER)."""
    from credproxy_cli.core import lifecycle
    calls = []
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_run(calls))
    ws = ws_factory("a")
    lifecycle.run_setup(ws, {"setup": ["id -u"]}, notify=lambda *_: None)
    cmd = calls[0]
    assert cmd[cmd.index("-u") + 1] == "0"
    assert cmd.index("-u") < cmd.index(ws.ws_container)


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


# ---- smart push: fingerprint, decision, status, enter --push -----------------


def test_config_fingerprint(xdg):
    from dataclasses import replace
    from credproxy_cli.core.bindings import Binding, config_fingerprint
    b = Binding(name="x", injector="bearer", provider="env", secret="TOK",
                hosts=("api.github.com",), placeholder="credproxy_PH", env="GH")
    fp = config_fingerprint([b])
    assert isinstance(fp, str) and len(fp) == 64          # sha256 hex
    assert config_fingerprint([b]) == fp                  # deterministic
    assert config_fingerprint([replace(b)]) == fp         # identical metadata
    assert config_fingerprint([replace(b, hosts=("z.com",))]) != fp
    assert config_fingerprint([replace(b, placeholder="credproxy_Q")]) != fp
    assert config_fingerprint([replace(b, secret="OTHER_REF")]) != fp  # ref change


def test_should_push_decision():
    from credproxy_cli.core.lifecycle import _should_push
    ok = {"loaded": True, "fingerprint": "x"}
    assert _should_push(True, False, ok, "x")                       # forced
    assert _should_push(False, True, None, "x")                     # proxy (re)started
    assert _should_push(False, False, None, "x")                    # unreachable
    assert _should_push(False, False, {"loaded": False}, "x")       # no config
    assert _should_push(False, False, {"loaded": True, "fingerprint": "y"}, "x")  # drift
    assert not _should_push(False, False, ok, "x")                  # match -> skip


def test_proxy_status_unreachable_is_none(xdg, ws_factory):
    from credproxy_cli.core.proxy_http import proxy_status
    ws = ws_factory("a")
    ws.ensure_state_dir()
    ws.token_path.write_text("tok")
    assert proxy_status(ws, 9) is None  # nothing listening on :9


def test_enter_push_flag_threads(xdg, ws_factory, monkeypatch):
    from test_porcelain import _run
    from credproxy_cli.core import lifecycle
    ws_factory("w")
    captured = {}

    def fake_enter(ws, cmd, notify=None, user_override=None, push=False):
        captured["push"] = push
        return 0
    monkeypatch.setattr(lifecycle, "enter_workspace", fake_enter)

    _run(["workspace", "w", "enter", "--", "true"])
    assert captured["push"] is False          # default: no forced push
    _run(["workspace", "w", "enter", "--push", "--", "true"])
    assert captured["push"] is True           # --push forces it


def test_setup_marker_and_retry(xdg, ws_factory):
    """Setup gate keyed on container id: no marker (fresh OR a failed prior
    attempt) -> run; same id after success -> skip; new id (recreate) -> run."""
    from credproxy_cli.core.lifecycle import (
        _read_setup_marker, _setup_needed, _write_setup_marker)
    ws = ws_factory("a")
    assert _read_setup_marker(ws) is None
    assert _setup_needed(None, "cid1") is True          # fresh / prior failure
    _write_setup_marker(ws, "cid1")                     # setup succeeded
    assert _read_setup_marker(ws) == "cid1"
    assert _setup_needed("cid1", "cid1") is False       # plain restart -> skip
    assert _setup_needed("cid1", "cid2") is True        # recreate -> re-run
    assert _setup_needed(None, "") is False             # defensive: no container
