"""Tests for porcelain/cli.py: strict/loose surface rules, --json shapes,
error serialization, default resolution, destructive gate, and list marking."""
from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest


# ---- driver ------------------------------------------------------------------


def _run(argv: list[str], *, stdin_text: str | None = None,
         stdin_isatty: bool = False) -> tuple[int, str, str]:
    """Run porcelain.cli.main() with the given argv, capturing stdout/stderr
    and the SystemExit code. Returns (exit_code, stdout, stderr)."""
    import io
    from credproxy_cli.porcelain import render

    # Reset the global renderer to human mode before each call.
    render.set_format(False)

    old_argv = sys.argv[:]
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    old_stdin = sys.stdin

    sys.argv = ["credproxy"] + argv
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()

    if stdin_text is not None:
        class FakeStdin:
            def __init__(self, text, tty):
                self._text = text
                self._tty = tty
                self._io = io.StringIO(text)

            def isatty(self):
                return self._tty

            def read(self, *a, **kw):
                return self._io.read(*a, **kw)

            def readline(self, *a, **kw):
                return self._io.readline(*a, **kw)

            def __iter__(self):
                return iter(self._io)

        sys.stdin = FakeStdin(stdin_text, stdin_isatty)

    exit_code = 0
    try:
        from credproxy_cli.porcelain.cli import main
        main(loose_default=False)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    finally:
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
        sys.argv = old_argv
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        sys.stdin = old_stdin
        render.set_format(False)

    return exit_code, stdout, stderr


def _run_loose(argv: list[str], **kw) -> tuple[int, str, str]:
    """Same as _run but with --loose pre-injected."""
    return _run(["--loose"] + argv, **kw)


# ---- strict: workspace name required -----------------------------------------


def test_strict_omit_name_fails(xdg, workspaces_dir):
    """Strict mode: `credproxy workspace start` without a name must fail."""
    ec, out, err = _run(["workspace", "start"])
    assert ec != 0
    # Strict surface: no default resolution
    assert "strict" in err or "required" in err or "usage" in err.lower()


def test_strict_unknown_command_fails(xdg):
    ec, out, err = _run(["badcmd"])
    assert ec != 0
    assert "unknown command" in err.lower() or "strict" in err.lower()


# ---- loose: default resolution announced on stderr ---------------------------


def test_loose_resolves_default_announced(xdg, workspaces_dir, monkeypatch):
    """Loose mode resolves the default workspace and announces it on stderr."""
    # Create workspace and set as default
    (workspaces_dir / "myws.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("myws"))

    # Stub docker so `start` doesn't actually run containers
    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.start_workspace",
        lambda ws, notify=None: notify("stub") if notify else None,
    )
    monkeypatch.setattr(
        "credproxy_cli.porcelain.cli.lifecycle.start_workspace",
        lambda ws, notify=None: None,
    )

    ec, out, err = _run_loose(["start"])
    # Default resolution must be announced on stderr
    assert "myws" in err
    assert "default" in err


def test_loose_no_default_fails(xdg, workspaces_dir):
    """Loose mode with no default set fails with a clear message."""
    ec, out, err = _run_loose(["start"])
    assert ec != 0
    assert "no default workspace" in err or "credp use" in err


# ---- reserved names rejected at create ---------------------------------------


def test_create_reserved_name_rejected(xdg):
    ec, out, err = _run(["workspace", "create", "delete"])
    assert ec != 0
    assert "reserved" in err.lower()


def test_create_reserved_name_binding(xdg):
    ec, out, err = _run(["workspace", "create", "binding"])
    assert ec != 0
    assert "reserved" in err.lower()


def test_create_reserved_name_list(xdg):
    ec, out, err = _run(["workspace", "create", "list"])
    assert ec != 0
    assert "reserved" in err.lower()


# ---- create / list ----------------------------------------------------------


def test_create_workspace_success(xdg, workspaces_dir):
    ec, out, err = _run(["workspace", "create", "myproj"])
    assert ec == 0, f"stderr: {err}"
    assert "myproj" in out
    assert (workspaces_dir / "myproj.toml").exists()


def test_list_marks_default(xdg, workspaces_dir, monkeypatch):
    """list output marks the default workspace with *."""
    for name in ("alpha", "bravo"):
        (workspaces_dir / f"{name}.toml").write_text('image = "x"\n')

    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("alpha"))

    # docker is lazily imported inside list_workspaces; patch the module attr.
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)

    ec, out, _ = _run(["list"])
    assert ec == 0
    lines = out.splitlines()
    alpha_line = next((l for l in lines if "alpha" in l), None)
    bravo_line = next((l for l in lines if "bravo" in l), None)
    assert alpha_line is not None
    assert bravo_line is not None
    assert "*" in alpha_line
    assert "*" not in bravo_line


# ---- --json output shapes ----------------------------------------------------


def test_json_create(xdg, workspaces_dir):
    ec, out, _ = _run(["--json", "workspace", "create", "jsonws"])
    assert ec == 0
    data = json.loads(out)
    assert data["name"] == "jsonws"
    assert "config_path" in data


def test_json_list(xdg, workspaces_dir, monkeypatch):
    (workspaces_dir / "j1.toml").write_text('image = "x"\n')
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)
    ec, out, _ = _run(["--json", "list"])
    assert ec == 0
    rows = json.loads(out)
    assert isinstance(rows, list)
    assert rows[0]["name"] == "j1"


def test_json_error_shape(xdg):
    """In --json mode, errors serialize as {"error": {"type": ..., "message": ...}}."""
    ec, out, err = _run(["--json", "workspace", "create", "delete"])
    assert ec != 0
    data = json.loads(out)
    assert "error" in data
    assert "type" in data["error"]
    assert "message" in data["error"]


def test_json_error_nonzero_exit(xdg):
    """--json errors still exit non-zero."""
    ec, out, _ = _run(["--json", "workspace", "start"])  # missing name in strict
    assert ec != 0


# ---- destructive gate: delete -----------------------------------------------


def test_delete_explicit_no_prompt(xdg, workspaces_dir, monkeypatch):
    """Explicit name never prompts even in loose mode."""
    (workspaces_dir / "target.toml").write_text('image = "x"\n')

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.delete_workspace",
        lambda ws: None,
    )

    ec, out, err = _run_loose(["workspace", "target", "delete"])
    # Should not fail or prompt
    assert ec == 0


def test_delete_implicit_non_tty_fails(xdg, workspaces_dir, monkeypatch):
    """Implicit delete without --yes and no TTY fails closed."""
    (workspaces_dir / "target.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("target"))

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.delete_workspace",
        lambda ws: None,
    )

    # stdin is not a tty (default in _run)
    ec, out, err = _run_loose(["delete"])
    assert ec != 0
    assert "stdin is not a TTY" in err or "pass --yes" in err


def test_delete_implicit_yes_bypasses_gate(xdg, workspaces_dir, monkeypatch):
    """--yes bypasses the implicit destructive gate."""
    (workspaces_dir / "target.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("target"))

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.delete_workspace",
        lambda ws: None,
    )

    ec, out, err = _run_loose(["--yes", "delete"])
    assert ec == 0


def test_delete_implicit_tty_yes_answer(xdg, workspaces_dir, monkeypatch):
    """When stdin is a TTY and user answers 'y', delete proceeds."""
    (workspaces_dir / "target.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("target"))

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.delete_workspace",
        lambda ws: None,
    )

    ec, out, err = _run_loose(["delete"], stdin_text="y\n", stdin_isatty=True)
    assert ec == 0


def test_delete_implicit_tty_no_answer_aborts(xdg, workspaces_dir, monkeypatch):
    """When stdin is a TTY and user answers 'n', delete aborts."""
    (workspaces_dir / "target.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("target"))

    monkeypatch.setattr(
        "credproxy_cli.core.lifecycle.delete_workspace",
        lambda ws: None,
    )

    ec, out, err = _run_loose(["delete"], stdin_text="n\n", stdin_isatty=True)
    assert ec != 0
    assert "aborted" in err.lower()


# ---- binding remove: destructive gate ----------------------------------------


def test_binding_remove_implicit_non_tty_fails(xdg, workspaces_dir, monkeypatch):
    """Implicit binding remove without TTY or --yes fails closed."""
    (workspaces_dir / "ws.toml").write_text("""\
image = "x"

[[binding]]
name = "myb"
injector = "github"
provider = "env"
secret = "X"
hosts = ["api.github.com"]
placeholder = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
""")
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("ws"))

    ec, out, err = _run_loose(["binding", "remove", "myb"])
    assert ec != 0
    assert "stdin is not a TTY" in err or "pass --yes" in err


def test_binding_remove_implicit_yes_proceeds(xdg, workspaces_dir, monkeypatch):
    """--yes lets implicit binding remove proceed."""
    (workspaces_dir / "ws.toml").write_text("""\
image = "x"

[[binding]]
name = "myb"
injector = "github"
provider = "env"
secret = "X"
hosts = ["api.github.com"]
placeholder = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
""")
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("ws"))

    ec, out, err = _run_loose(["--yes", "binding", "remove", "myb"])
    assert ec == 0


# ---- strict: no alias verbs --------------------------------------------------


def test_strict_alias_enter_fails(xdg):
    """Strict mode: top-level `enter` is not a recognized command."""
    ec, out, err = _run(["enter"])
    assert ec != 0
    assert "unknown command" in err.lower() or "strict" in err.lower()


# ---- help / no args ----------------------------------------------------------


def test_help_exits_zero(xdg):
    # _print_help() writes to stderr via say(); stdout is empty.
    ec, out, err = _run(["--help"])
    assert ec == 0
    # Help goes to stderr (say() prefix) or stdout -- accept either.
    combined = out + err
    assert "credproxy" in combined.lower() or "workspace" in combined


def test_no_args_exits_zero(xdg):
    """No args prints help and exits 0."""
    ec, out, err = _run([])
    assert ec == 0


def test_strict_help_is_strict(xdg):
    """Bare `credproxy` help describes the strict surface and points to credp."""
    ec, out, err = _run([])
    combined = out + err
    assert "Strict surface" in combined
    assert "credp" in combined  # points to the human alias


def test_loose_help_is_loose(xdg):
    """`credp` (loose) help leads with the short aliases and the default-
    workspace behavior -- and does NOT mislabel itself as the strict binary."""
    ec, out, err = _run_loose([])
    assert ec == 0
    combined = out + err
    assert "human surface" in combined
    assert "credp enter" in combined        # the aliases the loose user needs
    assert "current default" in combined or "the default" in combined
    assert "Strict surface" not in combined  # no third-person self-description


def test_loose_help_via_help_flag(xdg):
    """`credp --help` resolves the loose surface too (not just bare invocation)."""
    ec, out, err = _run(["--loose", "--help"])
    assert ec == 0
    assert "human surface" in (out + err)
