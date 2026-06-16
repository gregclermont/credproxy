"""Tests for core/pointer.py: read/set/clear/resolve default workspace pointer."""
from __future__ import annotations

import pytest


# ---- read_default ------------------------------------------------------------


def test_read_default_absent(xdg):
    from credproxy_cli.core.pointer import read_default

    assert read_default() is None


def test_read_default_empty_file(xdg):
    from credproxy_cli.core.paths import state_dir
    from credproxy_cli.core.pointer import read_default

    p = state_dir() / "default-workspace"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("   \n")
    assert read_default() is None


# ---- set_default / read_default ----------------------------------------------


def test_set_and_read_default(xdg, workspaces_dir):
    from credproxy_cli.core.pointer import read_default, set_default
    from credproxy_cli.core.workspace import Workspace

    # workspace must exist
    (workspaces_dir / "myws.toml").write_text('image = "x"\n')
    ws = Workspace("myws")
    set_default(ws)
    assert read_default() == "myws"


def test_set_default_failure_preserves_prior_pointer(xdg, workspaces_dir, monkeypatch):
    """A crash mid-write must NOT blank the default pointer (the write is atomic):
    the previously-set default survives a failed `set_default`."""
    import os

    from credproxy_cli.core.pointer import read_default, set_default
    from credproxy_cli.core.workspace import Workspace

    for n in ("a", "b"):
        (workspaces_dir / f"{n}.toml").write_text('image = "x"\n')
    set_default(Workspace("a"))
    assert read_default() == "a"

    def boom(*_a):
        raise OSError("simulated crash during rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        set_default(Workspace("b"))
    assert read_default() == "a"          # still 'a', never blanked


def test_set_default_nonexistent_raises(xdg, workspaces_dir):
    from credproxy_cli.core.errors import WorkspaceError
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace

    ws = Workspace("ghost")
    with pytest.raises(WorkspaceError, match="not found"):
        set_default(ws)


# ---- clear_default -----------------------------------------------------------


def test_clear_default_removes_pointer(xdg, workspaces_dir):
    from credproxy_cli.core.pointer import clear_default, read_default, set_default
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "myws.toml").write_text('image = "x"\n')
    set_default(Workspace("myws"))
    clear_default()
    assert read_default() is None


def test_clear_default_when_absent_is_noop(xdg):
    from credproxy_cli.core.pointer import clear_default

    clear_default()  # should not raise


# ---- resolve_default ---------------------------------------------------------


def test_resolve_default_no_pointer(xdg):
    from credproxy_cli.core.errors import WorkspaceError
    from credproxy_cli.core.pointer import resolve_default

    with pytest.raises(WorkspaceError, match="no default workspace"):
        resolve_default()


def test_resolve_default_points_to_deleted_workspace(xdg, workspaces_dir):
    """Pointer pointing to a nonexistent workspace raises WorkspaceError."""
    from credproxy_cli.core.paths import state_dir
    from credproxy_cli.core.errors import WorkspaceError
    from credproxy_cli.core.pointer import resolve_default

    p = state_dir() / "default-workspace"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("deleted_ws\n")

    with pytest.raises(WorkspaceError, match="no longer exists"):
        resolve_default()


def test_resolve_default_returns_workspace(xdg, workspaces_dir):
    from credproxy_cli.core.pointer import resolve_default, set_default
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "proj.toml").write_text('image = "x"\n')
    ws = Workspace("proj")
    set_default(ws)
    resolved = resolve_default()
    assert resolved.name == "proj"
