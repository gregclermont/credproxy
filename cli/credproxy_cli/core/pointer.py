"""The current-default-workspace pointer.

A single global file holding one workspace name (plain text). It persists
across shells and is consulted only by the loose/human surface to resolve an
omitted workspace; the strict surface never reads it.

Stored at $XDG_STATE_HOME/credproxy/default-workspace (a sibling of the
per-workspace state dirs). The core only reads/writes/clears the file and
validates that a pointed-to workspace exists; the *policy* of when to consult
it lives entirely in porcelain.
"""
from __future__ import annotations

from .errors import WorkspaceError
from .paths import state_dir
from .workspace import Workspace, for_name


def pointer_path():
    """Path to the default-workspace pointer file."""
    return state_dir() / "default-workspace"


def read_default() -> str | None:
    """Return the pointed-to workspace name, or None if unset/empty."""
    p = pointer_path()
    if not p.exists():
        return None
    name = p.read_text().strip()
    return name or None


def set_default(ws: Workspace) -> None:
    """Point the default at an existing workspace. Raises WorkspaceError if
    the workspace does not exist (the pointer must never name a phantom)."""
    if not ws.exists():
        raise WorkspaceError(f"workspace '{ws.name}' not found")
    p = pointer_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(ws.name + "\n")


def clear_default() -> None:
    """Remove the pointer file if present (best-effort)."""
    p = pointer_path()
    if p.exists():
        p.unlink()


def resolve_default() -> Workspace:
    """Resolve the pointer to a concrete, existing Workspace, or raise a
    clear WorkspaceError telling the user to set one. Used by the loose
    surface when a workspace argument is omitted."""
    name = read_default()
    if name is None:
        raise WorkspaceError(
            "no default workspace; run `credp use <name>` to set one"
        )
    ws = for_name(name)
    if not ws.exists():
        raise WorkspaceError(
            f"default workspace '{name}' no longer exists; "
            f"run `credp use <name>` to set a new one"
        )
    return ws
