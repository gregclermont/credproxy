"""Shared fixtures for CLI host-side tests.

Sets up a temporary XDG environment (config + state dirs isolated per test)
and adds the cli/ directory to sys.path so credproxy_cli can be imported
without installation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure cli/ is importable from any cwd.
_CLI_DIR = str(Path(__file__).resolve().parents[2] / "cli")
if _CLI_DIR not in sys.path:
    sys.path.insert(0, _CLI_DIR)


@pytest.fixture
def xdg(tmp_path, monkeypatch):
    """Temporary XDG dirs; patched into os.environ so all path helpers
    in credproxy_cli.core.paths pick them up at call time."""
    cfg = tmp_path / "config"
    state = tmp_path / "state"
    cfg.mkdir()
    state.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    return {"config": cfg, "state": state}


@pytest.fixture
def workspaces_dir(xdg):
    """Create and return the workspaces config dir."""
    from credproxy_cli.core.paths import workspaces_config_dir
    d = workspaces_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def ws_factory(xdg, workspaces_dir):
    """Return a factory that creates a minimal workspace TOML and returns
    the Workspace object."""
    def make(name: str, content: str | None = None) -> "Workspace":
        from credproxy_cli.core.workspace import Workspace
        path = workspaces_dir / f"{name}.toml"
        if content is None:
            content = f'image = "python:3.12-slim"\n'
        path.write_text(content)
        return Workspace(name)
    return make
