"""The Workspace value object and its host-side token.

A Workspace bundles the host-side paths and Docker object names derived
from a workspace name. Name validation lives here; the core only ever
receives concrete, valid names (porcelain resolves the default first),
but `for_name` re-validates so a bad name from any caller is a typed
error rather than a malformed container reference.

Storage layout (XDG):
  Config:  $XDG_CONFIG_HOME/credproxy/workspaces/<name>.toml
  State:   $XDG_STATE_HOME/credproxy/workspaces/<name>/
             auth.token         -- bearer token for the proxy API
             setup_done         -- container id that last COMPLETED setup
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .errors import WorkspaceError
from .paths import workspaces_config_dir, workspaces_state_dir

# Workspace names become container, volume, and directory names.
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")

# Verbs and sub-nouns that the `workspace` dispatcher peeks for. A workspace
# may not be named one of these, or `credproxy workspace <name> <verb>` would
# be ambiguous (is the token a name or a verb?). Enforced in `for_name` so a
# reserved name is a typed error wherever it enters the core.
# Must contain every CLI verb and top-level meta command, or a workspace could
# take a name the dispatcher reads as a verb (and become unaddressable). This
# duplicates the porcelain command sets because core must not import porcelain;
# `test_reserved_names_cover_all_cli_verbs` guards the two against drift.
RESERVED_NAMES = frozenset({
    # workspace-level verbs (used both name-before-verb and as bare verbs)
    "create", "use", "list", "enter", "edit", "start", "stop", "delete",
    "apply", "inspect", "config", "logs",
    # sub-noun
    "binding",
    # top-level meta commands (no workspace argument)
    "current",
})


@dataclass(frozen=True)
class Workspace:
    """A workspace's host-side paths and Docker object names, all
    derived from its name."""

    name: str

    @property
    def config_path(self) -> Path:
        """Per-workspace TOML config file."""
        return workspaces_config_dir() / f"{self.name}.toml"

    @property
    def state_dir(self) -> Path:
        """Per-workspace state directory (created on demand)."""
        return workspaces_state_dir() / self.name

    @property
    def token_path(self) -> Path:
        return self.state_dir / "auth.token"

    @property
    def setup_done_path(self) -> Path:
        """Marker file recording the container id that last COMPLETED setup.
        Written only on success, so a failed setup re-runs on the next start;
        keyed on container id, so a plain stop/start (same id) skips setup but a
        recreate (new id) re-runs it."""
        return self.state_dir / "setup_done"

    @property
    def applied_spec_path(self) -> Path:
        """JSON file recording the workspace launch spec that was last
        successfully applied (written when a workspace container is created)."""
        return self.state_dir / "applied-spec.json"

    @property
    def applied_bindings_path(self) -> Path:
        """JSON file recording binding metadata last pushed to the proxy
        (written after a successful push). No secret values."""
        return self.state_dir / "applied-bindings.json"

    @property
    def sessions_dir(self) -> Path:
        """Directory holding per-session pidfiles for auto-stop tracking."""
        return self.state_dir / "sessions"

    @property
    def proxy_container(self) -> str:
        return f"credproxy-proxy-{self.name}"

    @property
    def ws_container(self) -> str:
        return f"credproxy-ws-{self.name}"

    @property
    def home_volume(self) -> str:
        return f"credproxy-home-{self.name}"

    def exists(self) -> bool:
        """A workspace exists iff its config file exists."""
        return self.config_path.exists()

    def ensure_state_dir(self) -> None:
        """Create the per-workspace state dir if it doesn't exist yet."""
        self.state_dir.mkdir(parents=True, exist_ok=True)


def for_name(name: str) -> Workspace:
    """Build a Workspace for a concrete name, validating it. Raises
    WorkspaceError on an invalid name. Defaults are resolved in porcelain,
    so `name` is always a concrete string here."""
    if not _NAME_RE.match(name):
        raise WorkspaceError(
            f"invalid workspace name {name!r}: use letters, digits, "
            f"'.', '_', '-' (not starting with a separator)"
        )
    if name in RESERVED_NAMES:
        raise WorkspaceError(
            f"'{name}' is a reserved command name and cannot be a "
            f"workspace name"
        )
    return Workspace(name)


def list_names() -> list[str]:
    """All workspace names that have a config file, sorted."""
    d = workspaces_config_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.iterdir() if p.suffix == ".toml" and p.is_file())


@dataclass(frozen=True)
class WorkspaceStatus:
    name: str
    running: bool
    image: str


def list_workspaces() -> list[WorkspaceStatus]:
    """Structured status for every workspace: name, running?, image.

    Docker is queried for the running state; image is read from the TOML."""
    from . import docker
    from .config import quick_image

    out = []
    for name in list_names():
        ws = Workspace(name)
        running = docker.container_status(ws.ws_container) == "running"
        out.append(WorkspaceStatus(name, running, quick_image(ws)))
    return out


def ensure_token(ws: Workspace) -> None:
    """Create the workspace's bearer token if absent. Idempotent."""
    if ws.token_path.exists() and ws.token_path.read_text().strip():
        return
    ws.ensure_state_dir()
    ws.token_path.write_text(secrets.token_hex(16) + "\n")
    # 0644 so uid 31337 in the proxy can read it through the bind mount
    # (multi-user host limitation, documented in CLAUDE.md).
    ws.token_path.chmod(0o644)


def read_token(ws: Workspace) -> str:
    if not ws.token_path.exists():
        raise WorkspaceError(f"token missing: {ws.token_path}")
    token = ws.token_path.read_text().strip()
    if not token:
        raise WorkspaceError(f"token file empty: {ws.token_path}")
    return token
