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


# ---- loose: cwd-addressed resolution -----------------------------------------


def test_loose_resolves_by_cwd_announced(xdg, workspaces_dir, tmp_path, monkeypatch):
    """A loose command run from a workspace's `directory` resolves to it, and
    the cwd match is announced on stderr."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    monkeypatch.chdir(proj)
    ec, out, err = _run_loose(["config"])  # `config` reads the TOML, no docker
    assert ec == 0, f"stderr: {err}"
    assert "proj" in err
    assert "matched current directory" in err


def test_loose_cwd_beats_default(xdg, workspaces_dir, tmp_path, monkeypatch):
    """cwd resolution takes precedence over the default pointer."""
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace

    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    (workspaces_dir / "other.toml").write_text('image = "x"\n')
    set_default(Workspace("other"))
    monkeypatch.chdir(proj)
    ec, out, err = _run_loose(["config"])
    assert ec == 0, f"stderr: {err}"
    assert "matched current directory" in err
    assert "proj" in err and "other" not in err


def test_loose_falls_back_to_default_outside_any_dir(xdg, workspaces_dir, tmp_path, monkeypatch):
    """With no cwd match, resolution falls back to the default pointer."""
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "deflt.toml").write_text('image = "x"\n')
    set_default(Workspace("deflt"))
    monkeypatch.chdir(tmp_path)  # unrelated dir
    ec, out, err = _run_loose(["config"])
    assert ec == 0, f"stderr: {err}"
    assert "deflt" in err and "default" in err


def test_strict_ignores_cwd(xdg, workspaces_dir, tmp_path, monkeypatch):
    """The strict surface never consults cwd -- a name is still required."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    monkeypatch.chdir(proj)
    ec, out, err = _run(["workspace", "config"])  # strict, no name
    assert ec != 0
    assert "required" in err or "strict" in err or "usage" in err.lower()


# ---- create --here / --dir ---------------------------------------------------


def test_create_here_associates_cwd(xdg, workspaces_dir, tmp_path, monkeypatch):
    import os
    from credproxy_cli.core.config import quick_directory
    from credproxy_cli.core.workspace import Workspace

    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run(["workspace", "create", "proj", "--here"])
    assert ec == 0, f"stderr: {err}"
    got = quick_directory(Workspace("proj"))
    assert got and os.path.realpath(got) == os.path.realpath(str(proj))


def test_create_dir_associates_path(xdg, workspaces_dir, tmp_path):
    import os
    from credproxy_cli.core.config import quick_directory
    from credproxy_cli.core.workspace import Workspace

    target = tmp_path / "code"
    target.mkdir()
    ec, out, err = _run(["workspace", "create", "w", "--dir", str(target)])
    assert ec == 0, f"stderr: {err}"
    got = quick_directory(Workspace("w"))
    assert got and os.path.realpath(got) == os.path.realpath(str(target))


def test_create_here_and_dir_conflict(xdg, workspaces_dir, tmp_path):
    ec, out, err = _run(["workspace", "create", "w", "--here", "--dir", str(tmp_path)])
    assert ec != 0
    assert "not both" in err


def test_create_here_then_resolves(xdg, workspaces_dir, tmp_path, monkeypatch):
    """End-to-end: create --here writes valid TOML that cwd-resolution reads."""
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run(["workspace", "create", "proj", "--here"])
    assert ec == 0, f"stderr: {err}"
    ec, out, err = _run_loose(["config"])
    assert ec == 0, f"stderr: {err}"
    assert "matched current directory" in err


# ---- nameless create (name derived from the directory) -----------------------


def test_create_here_nameless_derives(xdg, workspaces_dir, tmp_path, monkeypatch):
    proj = tmp_path / "coolproj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run_loose(["create", "--here"])
    assert ec == 0, f"stderr: {err}"
    assert (workspaces_dir / "coolproj.toml").exists()
    assert "derived" in err and "coolproj" in err


def test_create_dir_nameless_derives(xdg, workspaces_dir, tmp_path):
    target = tmp_path / "widget"
    target.mkdir()
    ec, out, err = _run_loose(["create", "--dir", str(target)])
    assert ec == 0, f"stderr: {err}"
    assert (workspaces_dir / "widget.toml").exists()


def test_create_nameless_dedups(xdg, workspaces_dir, tmp_path, monkeypatch):
    (workspaces_dir / "dup.toml").write_text('image = "x"\n')
    proj = tmp_path / "dup"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run_loose(["create", "--here"])
    assert ec == 0, f"stderr: {err}"
    assert (workspaces_dir / "dup-2.toml").exists()


def test_create_strict_nameless_errors(xdg, workspaces_dir, tmp_path, monkeypatch):
    """Strict surface never derives -- a name is required even with --here."""
    proj = tmp_path / "p"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run(["workspace", "create", "--here"])
    assert ec != 0
    assert "required" in err


def test_create_loose_nameless_no_dir_errors(xdg, workspaces_dir):
    """Loose, no NAME and no --here/--dir: nothing to derive from."""
    ec, out, err = _run_loose(["create"])
    assert ec != 0
    assert "derive" in err


# ---- bind-dir ----------------------------------------------------------------


def test_bind_dir_defaults_to_cwd(xdg, workspaces_dir, tmp_path, monkeypatch):
    import os
    from credproxy_cli.core.config import quick_directory
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "w.toml").write_text('image = "x"\n')
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run(["workspace", "w", "bind-dir"])
    assert ec == 0, f"stderr: {err}"
    got = quick_directory(Workspace("w"))
    assert got and os.path.realpath(got) == os.path.realpath(str(proj))


def test_bind_dir_explicit_path_replaces(xdg, workspaces_dir, tmp_path):
    import os
    from credproxy_cli.core.config import quick_directory
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "w.toml").write_text('image = "x"\ndirectory = "/old/path"\n')
    target = tmp_path / "new"
    target.mkdir()
    ec, out, err = _run(["workspace", "w", "bind-dir", "--dir", str(target)])
    assert ec == 0, f"stderr: {err}"
    got = quick_directory(Workspace("w"))
    assert os.path.realpath(got) == os.path.realpath(str(target))
    assert "/old/path" not in (workspaces_dir / "w.toml").read_text()


def test_bind_dir_loose_default_workspace(xdg, workspaces_dir, tmp_path, monkeypatch):
    import os
    from credproxy_cli.core.config import quick_directory
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "w.toml").write_text('image = "x"\n')
    set_default(Workspace("w"))
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    ec, out, err = _run_loose(["bind-dir"])  # default workspace, cwd
    assert ec == 0, f"stderr: {err}"
    got = quick_directory(Workspace("w"))
    assert got and os.path.realpath(got) == os.path.realpath(str(proj))


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


def test_config_effective_fills_enter_time_defaults(xdg, workspaces_dir):
    """`config` (effective) shows workdir/enter_prelude with their in-effect
    values even when absent from the file."""
    import json
    (workspaces_dir / "w.toml").write_text('image = "alpine:3"\nhome = "/home/dev"\n')
    ec, out, err = _run(["--json", "workspace", "w", "config"])
    assert ec == 0, f"stderr: {err}"
    cfg = json.loads(out)["config"]
    assert json.loads(out)["mode"] == "effective"
    assert cfg["workdir"] == "/home/dev"           # resolved from home
    assert cfg["enter_prelude"] is not None        # resolved to the shim default


def test_config_declared_shows_only_file_keys(xdg, workspaces_dir):
    """`config --declared` shows only what's literally in the TOML."""
    import json
    (workspaces_dir / "w.toml").write_text('image = "alpine:3"\nhome = "/home/dev"\n')
    ec, out, err = _run(["--json", "workspace", "w", "config", "--declared"])
    assert ec == 0, f"stderr: {err}"
    data = json.loads(out)
    assert data["mode"] == "declared"
    assert data["config"] == {"image": "alpine:3", "home": "/home/dev"}


def test_config_reserved_name(xdg):
    """`config` is a reserved verb -> can't be a workspace name."""
    ec, _, err = _run(["workspace", "create", "config"])
    assert ec != 0
    assert "reserved" in err


def test_list_marks_default(xdg, workspaces_dir, monkeypatch):
    """Loose list marks the default workspace with *."""
    for name in ("alpha", "bravo"):
        (workspaces_dir / f"{name}.toml").write_text('image = "x"\n')

    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("alpha"))

    # docker is lazily imported inside list_workspaces; patch the module attr.
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)

    ec, out, _ = _run_loose(["list"])
    assert ec == 0
    lines = out.splitlines()
    alpha_line = next((l for l in lines if "alpha" in l), None)
    bravo_line = next((l for l in lines if "bravo" in l), None)
    assert alpha_line is not None
    assert bravo_line is not None
    assert "*" in alpha_line
    assert "*" not in bravo_line
    # No workspace has a directory -> the DIRECTORY column stays hidden (output
    # unchanged from before the feature).
    assert "DIRECTORY" not in out


def test_list_strict_is_plain_inventory(xdg, workspaces_dir, tmp_path, monkeypatch):
    """Strict list consults neither the default pointer nor cwd: no `*`/`→`
    markers and no legend (the DIRECTORY column is factual config and stays)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    (workspaces_dir / "bravo.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("proj"))
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)
    monkeypatch.chdir(proj)

    ec, out, err = _run(["list"])  # strict
    assert ec == 0, f"stderr: {err}"
    assert "*" not in out          # no default marker on strict
    assert "→" not in out and "→" not in err  # no cwd marker/legend on strict
    assert "markers:" not in err
    assert "DIRECTORY" in out      # factual config column still shows


def test_list_shows_directory_and_cwd_marker(xdg, workspaces_dir, tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    (workspaces_dir / "plain.toml").write_text('image = "x"\n')
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)
    monkeypatch.chdir(proj)

    ec, out, err = _run_loose(["list"])
    assert ec == 0, f"stderr: {err}"
    assert "DIRECTORY" in out
    # The cwd match is flagged by a `→` marker on its row, and the new marker is
    # explained by a stderr legend.
    cwd_line = next(l for l in out.splitlines() if "proj" in l and "→" in l)
    assert "→" in cwd_line
    assert "markers:" in err and "current directory" in err


def test_list_json_includes_directory_and_here(xdg, workspaces_dir, tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    import credproxy_cli.core.docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "container_status", lambda name: None)
    monkeypatch.chdir(proj)

    ec, out, err = _run_loose(["--json", "list"])
    assert ec == 0, f"stderr: {err}"
    row = next(r for r in json.loads(out) if r["name"] == "proj")
    assert row["here"] is True
    assert row["directory"]


def test_current_is_loose_only(xdg, workspaces_dir):
    """`current` reports the loose default/cwd resolution -- the strict surface
    disclaims implicit targeting (like the loose-only writer, `use`)."""
    (workspaces_dir / "alpha.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("alpha"))

    ec, _, err = _run(["current"])  # strict
    assert ec != 0
    assert "loose-only" in err


def test_current_loose_cwd_shadows_default(xdg, workspaces_dir, tmp_path, monkeypatch):
    """In a cwd-matched directory, loose `current` reports the cwd workspace as
    the effective target on stdout and names the shadowed default on stderr."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    (workspaces_dir / "backend.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("backend"))
    monkeypatch.chdir(proj)

    ec, out, err = _run_loose(["current"])
    assert ec == 0, f"stderr: {err}"
    assert out.strip() == "proj"
    assert "current directory" in err
    assert "backend" in err  # the shadowed default is surfaced


def test_current_loose_no_cwd_is_default(xdg, workspaces_dir, tmp_path, monkeypatch):
    """With no cwd match, loose `current` falls to the default pointer and says
    so on stderr."""
    (workspaces_dir / "backend.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("backend"))
    monkeypatch.chdir(tmp_path)

    ec, out, err = _run_loose(["current"])
    assert ec == 0, f"stderr: {err}"
    assert out.strip() == "backend"
    assert "default" in err


def test_current_json_carries_workspace_source_default(xdg, workspaces_dir, tmp_path, monkeypatch):
    """`--json current` reports the effective target, its source, and the
    default pointer, unconflated."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (workspaces_dir / "proj.toml").write_text(f'image = "x"\ndirectory = "{proj}"\n')
    (workspaces_dir / "backend.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("backend"))
    monkeypatch.chdir(proj)

    ec, out, _ = _run_loose(["--json", "current"])
    assert ec == 0
    data = json.loads(out)
    assert data == {"workspace": "proj", "source": "directory", "default": "backend"}


# ---- info (centralized config & state) ---------------------------------------


def test_info_shows_paths_and_registries(xdg, workspaces_dir):
    """`info` dumps the global config/state: resolved roots, proxy image, and a
    three-tier registry breakdown (builtins always present)."""
    ec, out, err = _run(["info"])
    assert ec == 0, f"stderr: {err}"
    assert "paths" in out and "registries" in out
    assert "config" in out and "state" in out and "builtin" in out
    assert "credproxy:dev" in out  # IMAGE_TAG
    assert "injectors" in out and "providers" in out


def test_info_default_workspace_is_loose_only(xdg, workspaces_dir):
    """The default pointer is a loose concept: strict `info` omits it, loose
    `info` shows it (consistent with `list`/`current`)."""
    (workspaces_dir / "backend.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("backend"))

    _, strict_out, _ = _run(["info"])
    assert "default workspace" not in strict_out

    _, loose_out, _ = _run_loose(["info"])
    assert "default workspace" in loose_out and "backend" in loose_out


def test_info_json_shape(xdg, workspaces_dir):
    """`--json info` carries the full centralized state; loose adds the default
    pointer, strict omits it."""
    ec, out, _ = _run_loose(["--json", "info"])
    assert ec == 0
    d = json.loads(out)
    assert d["proxy_image"] == "credproxy:dev"
    assert set(d["paths"]) >= {"config", "state", "profile", "builtin", "profile_present"}
    for kind in ("injectors", "providers", "scripts", "presets"):
        assert set(d["registries"][kind]) == {"user", "profile", "builtin"}
    assert "default_workspace" in d           # loose
    assert "XDG_CONFIG_HOME" in d["env"]

    _, strict_out, _ = _run(["--json", "info"])
    assert "default_workspace" not in json.loads(strict_out)  # strict omits it


def test_info_counts_profile_overrides(xdg, workspaces_dir, tmp_path, monkeypatch):
    """A profile-overlay injector is counted in the `profile` tier and bumps the
    profile override count -- the 'is my overlay active?' signal."""
    profile = tmp_path / "prof"
    (profile / "injectors").mkdir(parents=True)
    (profile / "injectors" / "orgtok.toml").write_text(
        'scheme = "bearer"\nlocation = "header"\n')
    monkeypatch.setenv("CREDPROXY_PROFILE_DIR", str(profile))

    ec, out, _ = _run_loose(["--json", "info"])
    assert ec == 0
    d = json.loads(out)
    assert d["registries"]["injectors"]["profile"] >= 1
    assert d["profile_overrides"] >= 1
    assert d["paths"]["profile_present"] is True


def test_info_rejects_extra_args(xdg, workspaces_dir):
    ec, out, err = _run(["info", "extra"])
    assert ec != 0 and "no arguments" in (out + err)


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
        lambda ws, keep_volumes=False: None,
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
        lambda ws, keep_volumes=False: None,
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
        lambda ws, keep_volumes=False: None,
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
        lambda ws, keep_volumes=False: None,
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
        lambda ws, keep_volumes=False: None,
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


# ---- loose create seeds the default pointer when empty -----------------------


def test_loose_create_seeds_default_when_unset(xdg, workspaces_dir):
    """In loose mode, creating a workspace with no default set makes it the
    default (announced), so `credp enter` works immediately."""
    from credproxy_cli.core.pointer import read_default
    assert read_default() is None

    ec, out, err = _run_loose(["create", "alpha"])
    assert ec == 0
    assert read_default() == "alpha"
    assert "default workspace" in err  # announced on stderr


def test_loose_create_does_not_override_existing_default(xdg, workspaces_dir):
    """The seed only fills a vacuum -- a second create never changes an
    already-selected default."""
    from credproxy_cli.core.pointer import read_default

    _run_loose(["create", "alpha"])            # alpha becomes default
    ec, out, err = _run_loose(["create", "beta"])
    assert ec == 0
    assert read_default() == "alpha"           # unchanged
    assert "default workspace" not in err      # nothing announced


def test_strict_create_never_sets_default(xdg, workspaces_dir):
    """Strict `create` has no default-workspace behavior -- the pointer stays
    unset."""
    from credproxy_cli.core.pointer import read_default

    ec, out, err = _run(["workspace", "create", "alpha"])
    assert ec == 0
    assert read_default() is None


def test_loose_create_reseeds_after_default_cleared(xdg, workspaces_dir):
    """Deleting the default clears the pointer; the next loose create re-seeds
    it (the vacuum is real again)."""
    from credproxy_cli.core.pointer import read_default, clear_default

    _run_loose(["create", "alpha"])
    clear_default()                            # simulate delete-of-default
    assert read_default() is None
    _run_loose(["create", "beta"])
    assert read_default() == "beta"


def test_edit_rejects_json(xdg, ws_factory):
    ws_factory("a")
    ec, out, err = _run(["--json", "workspace", "a", "edit"])
    assert ec != 0
    assert "json" in (out + err).lower()


def test_edit_missing_workspace_fails(xdg):
    ec, out, err = _run(["workspace", "nope", "edit"])
    assert ec != 0


def test_edit_valid_config_hints_apply(xdg, ws_factory, monkeypatch):
    """A clean edit (no-op editor) validates and hints that changes aren't live."""
    ws_factory("a")
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", "true")  # no-op editor, leaves file valid
    ec, out, err = _run(["workspace", "a", "edit"])
    assert ec == 0
    assert "apply" in err or "not live" in err


def test_edit_invalid_config_warns(xdg, ws_factory, tmp_path, monkeypatch):
    """If the edit leaves the config invalid, edit succeeds but warns (it never
    reverts the user's file)."""
    ws_factory("a")
    ed = tmp_path / "corrupting_editor.sh"
    ed.write_text('#!/bin/sh\nprintf "this is not valid toml\\n" >> "$1"\n')
    ed.chmod(0o755)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", str(ed))
    ec, out, err = _run(["workspace", "a", "edit"])
    assert ec == 0  # editing succeeded; validation only warns
    assert "invalid" in err.lower()


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


# ---- recreate ----------------------------------------------------------------


def _stub_recreate(monkeypatch):
    """Replace lifecycle.recreate_workspace with a recorder of
    (include_proxy, reset_volumes)."""
    calls: list = []
    monkeypatch.setattr(
        "credproxy_cli.porcelain.cli.lifecycle.recreate_workspace",
        lambda ws, notify=None, include_proxy=False, reset_volumes=None:
            calls.append((include_proxy, reset_volumes or [])),
    )
    return calls


def test_recreate_strict_requires_name(xdg, workspaces_dir):
    """Strict surface: `workspace recreate` without a name fails (no default)."""
    ec, out, err = _run(["workspace", "recreate"])
    assert ec != 0


def test_recreate_default_is_workspace_only(xdg, workspaces_dir, monkeypatch):
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run(["workspace", "rc", "recreate"])
    assert ec == 0, err
    assert calls == [(False, [])]                     # proxy + home untouched


def test_recreate_proxy_flag_includes_proxy(xdg, workspaces_dir, monkeypatch):
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run(["workspace", "rc", "recreate", "--proxy"])
    assert ec == 0, err
    assert calls == [(True, [])]


def test_recreate_all_is_alias_for_proxy(xdg, workspaces_dir, monkeypatch):
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run(["workspace", "rc", "recreate", "--all"])
    assert ec == 0, err
    assert calls == [(True, [])]


def test_recreate_loose_alias_resolves_default(xdg, workspaces_dir, monkeypatch):
    """`credp recreate` (no name) resolves the default workspace."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("rc"))
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run_loose(["recreate"])
    assert ec == 0, err
    assert calls == [(False, [])]


# ---- recreate --reset-volume: flag plumbing + destructive gate ---------------


def test_recreate_reset_volume_flag_passed_through(xdg, workspaces_dir, monkeypatch):
    """Explicit target on the strict surface: --reset-volume home plumbs through with
    no prompt (scriptable, like delete)."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run(["workspace", "rc", "recreate", "--reset-volume", "home"])
    assert ec == 0, err
    assert calls == [(False, ["home"])]


def test_recreate_reset_volume_implicit_non_tty_fails(xdg, workspaces_dir, monkeypatch):
    """Gated like delete: --reset-volume home on an implicit default, no TTY/--yes,
    fails closed and never calls through."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("rc"))
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run_loose(["recreate", "--reset-volume", "home"])
    assert ec != 0
    assert "stdin is not a TTY" in err or "pass --yes" in err
    assert calls == []


def test_recreate_reset_volume_implicit_yes_bypasses(xdg, workspaces_dir, monkeypatch):
    """--yes bypasses the gate; --reset-volume home then proceeds."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("rc"))
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run_loose(["--yes", "recreate", "--reset-volume", "home"])
    assert ec == 0, err
    assert calls == [(False, ["home"])]


def test_recreate_reset_volume_implicit_tty_no_aborts(xdg, workspaces_dir, monkeypatch):
    """TTY, answer 'n' -> aborts, no call through."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("rc"))
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run_loose(["recreate", "--reset-volume", "home"],
                              stdin_text="n\n", stdin_isatty=True)
    assert ec != 0
    assert "aborted" in err.lower()
    assert calls == []


def test_recreate_plain_implicit_not_gated(xdg, workspaces_dir, monkeypatch):
    """Plain recreate (no --reset-volume home) keeps all state, so it is NOT gated even
    on an implicit default with no TTY."""
    (workspaces_dir / "rc.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("rc"))
    calls = _stub_recreate(monkeypatch)
    ec, out, err = _run_loose(["recreate"])
    assert ec == 0, err
    assert calls == [(False, [])]


# ---- mount add ---------------------------------------------------------------


def _mkws(workspaces_dir, name="ws", body='image = "x"\n'):
    (workspaces_dir / f"{name}.toml").write_text(body)


def test_mount_add_plain_edits_toml(xdg, workspaces_dir):
    """A plain `mount add` (no --preserve) is a deferred config edit -- it writes
    the volume into the TOML and hints `start`; no container ops."""
    import tomllib
    _mkws(workspaces_dir)
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/c"])
    assert ec == 0, err
    raw = tomllib.loads((workspaces_dir / "ws.toml").read_text())
    assert {"volume": "cache", "target": "/c"} in raw["mounts"]
    assert "added volume 'cache'" in out
    assert "start" in err            # deferred-apply hint on stderr


def test_mount_add_user_owned_writes_flag(xdg, workspaces_dir):
    """`mount add --user-owned` persists `user_owned = true` (workspace has a
    non-root user)."""
    import tomllib
    _mkws(workspaces_dir, body='image = "x"\nuser = "dev"\n')
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/home/dev/.cache",
                         "--user-owned"])
    assert ec == 0, err
    raw = tomllib.loads((workspaces_dir / "ws.toml").read_text())
    vol = next(m for m in raw["mounts"] if m["volume"] == "cache")
    assert vol["user_owned"] is True


def test_mount_add_user_owned_needs_non_root_user(xdg, workspaces_dir):
    """--user-owned on a root workspace (no `user`) is rejected up front."""
    _mkws(workspaces_dir)  # image only, no user
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/c", "--user-owned"])
    assert ec != 0 and "non-root `user`" in err


def test_mount_add_home_user_owned_rejected(xdg, workspaces_dir):
    """The `home` sugar can't carry flags -> --user-owned on it is rejected with
    a hint to use an explicit [[mounts]] table."""
    _mkws(workspaces_dir, body='image = "x"\nuser = "dev"\n')
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "home", "--target", "/home/dev", "--user-owned"])
    assert ec != 0 and "can't carry user_owned" in err


def test_mount_add_requires_volume_and_target(xdg, workspaces_dir):
    _mkws(workspaces_dir)
    ec, out, err = _run(["workspace", "ws", "mount", "add", "--target", "/c"])
    assert ec != 0 and "--volume" in err
    ec, out, err = _run(["workspace", "ws", "mount", "add", "--volume", "cache"])
    assert ec != 0 and "--target" in err


def test_mount_add_duplicate_target_rejected(xdg, workspaces_dir):
    _mkws(workspaces_dir, body='image = "x"\nmounts = [{ volume = "a", target = "/c" }]\n')
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/c"])
    assert ec != 0 and "already mounts" in err


def test_mount_add_duplicate_name_rejected(xdg, workspaces_dir):
    _mkws(workspaces_dir, body='image = "x"\nmounts = [{ volume = "cache", target = "/x" }]\n')
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/c"])
    assert ec != 0 and "already has a volume named" in err


def test_mount_add_home_writes_sugar(xdg, workspaces_dir):
    import tomllib
    _mkws(workspaces_dir)
    ec, out, err = _run(["workspace", "ws", "mount", "add",
                         "--volume", "home", "--target", "/home/vscode"])
    assert ec == 0, err
    raw = tomllib.loads((workspaces_dir / "ws.toml").read_text())
    assert raw["home"] == "/home/vscode"
    assert "mounts" not in raw


def test_mount_add_json_shape(xdg, workspaces_dir):
    _mkws(workspaces_dir)
    ec, out, err = _run(["--json", "workspace", "ws", "mount", "add",
                         "--volume", "cache", "--target", "/c"])
    assert ec == 0, err
    obj = json.loads(out)
    assert obj["workspace"] == "ws"
    assert obj["mount"] == {"volume": "cache", "target": "/c", "readonly": False}
    assert obj["applied"] is False


def _stub_preserve_docker(monkeypatch, *, running=True, sessions=1):
    """Stub the runtime probes do_mount_add consults for the --preserve gate, and
    no-op the actual add so no real docker runs."""
    from credproxy_cli.core import docker as _d
    from credproxy_cli.core import lifecycle as _l
    monkeypatch.setattr(_d, "container_status",
                        lambda c: "running" if running else None)
    monkeypatch.setattr(_l, "_count_live_sessions", lambda ws, **kw: sessions)
    called = {}
    def _add(ws, **kw):
        called.update(kw)
    monkeypatch.setattr(_l, "add_managed_volume", _add)
    return called


def test_mount_add_preserve_strict_running_sessions_refuses(xdg, workspaces_dir, monkeypatch):
    """Strict surface: --preserve on a running workspace with live sessions
    refuses without --yes (never prompts)."""
    _mkws(workspaces_dir)
    _stub_preserve_docker(monkeypatch, running=True, sessions=2)
    ec, out, err = _run(["workspace", "ws", "mount", "add", "--volume", "cache",
                         "--target", "/c", "--preserve"])
    assert ec != 0
    assert "--yes" in err and "2 active session" in err


def test_mount_add_preserve_yes_bypasses(xdg, workspaces_dir, monkeypatch):
    _mkws(workspaces_dir)
    called = _stub_preserve_docker(monkeypatch, running=True, sessions=3)
    ec, out, err = _run(["workspace", "ws", "mount", "add", "--volume", "cache",
                         "--target", "/c", "--preserve", "--yes"])
    assert ec == 0, err
    assert called.get("preserve") is True


def test_mount_add_preserve_loose_no_tty_fails_closed(xdg, workspaces_dir, monkeypatch):
    _mkws(workspaces_dir)
    _stub_preserve_docker(monkeypatch, running=True, sessions=1)
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("ws"))
    ec, out, err = _run_loose(["mount", "add", "--volume", "cache",
                               "--target", "/c", "--preserve"])
    assert ec != 0
    assert "not a TTY" in err or "--yes" in err


def test_mount_add_preserve_loose_prompt_accepts(xdg, workspaces_dir, monkeypatch):
    _mkws(workspaces_dir)
    called = _stub_preserve_docker(monkeypatch, running=True, sessions=1)
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("ws"))
    ec, out, err = _run_loose(["mount", "add", "--volume", "cache", "--target",
                               "/c", "--preserve"],
                              stdin_text="y\n", stdin_isatty=True)
    assert ec == 0, err
    assert called.get("preserve") is True


def test_mount_add_preserve_no_sessions_not_gated(xdg, workspaces_dir, monkeypatch):
    """Running but idle (no sessions) is not gated -- behaves like plain recreate."""
    _mkws(workspaces_dir)
    called = _stub_preserve_docker(monkeypatch, running=True, sessions=0)
    ec, out, err = _run(["workspace", "ws", "mount", "add", "--volume", "cache",
                         "--target", "/c", "--preserve"])
    assert ec == 0, err
    assert called.get("preserve") is True


def test_mount_add_alias_resolves_default(xdg, workspaces_dir):
    """`credp mount add` (alias) acts on the resolved default workspace; the
    subcommand `add` is not mistaken for a workspace name."""
    import tomllib
    _mkws(workspaces_dir)
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("ws"))
    ec, out, err = _run_loose(["mount", "add", "--volume", "cache", "--target", "/c"])
    assert ec == 0, err
    raw = tomllib.loads((workspaces_dir / "ws.toml").read_text())
    assert {"volume": "cache", "target": "/c"} in raw["mounts"]


@pytest.mark.parametrize("action,flag,value", [
    ("block", "--body", "x"),
    ("block", "--resp-header", "K=V"),
    ("respond", "--resp-header", "K=V"),
    ("script", "--status", "404"),
])
def test_rule_add_rejects_out_of_action_flag(xdg, workspaces_dir, action, flag, value):
    """A flag that doesn't belong to the chosen action's subparser is rejected by
    argparse structurally (no rejection table). argparse fails before workspace
    resolution, so no workspace setup is needed."""
    ec, out, err = _run(["workspace", "w", "rule", "add", action,
                         "--host", "api.github.com", flag, value])
    assert ec != 0
    assert "unrecognized arguments" in err or flag in err


def test_rule_add_action_subcommand_happy_path(xdg, workspaces_dir):
    """`rule add block ...` (action as a subcommand) writes the [[rule]] table."""
    import tomllib
    _mkws(workspaces_dir)
    ec, out, err = _run(["workspace", "ws", "rule", "add", "block",
                         "--host", "api.github.com", "--method", "DELETE",
                         "--path", "/repos/**"])
    assert ec == 0, err
    raw = tomllib.loads((workspaces_dir / "ws.toml").read_text())
    assert raw["rule"][0]["action"] == "block"
    assert raw["rule"][0]["hosts"] == ["api.github.com"]
    assert raw["rule"][0]["methods"] == ["DELETE"]


def test_rule_add_no_action_fails(xdg, workspaces_dir):
    """`rule add` with no action subcommand is a friendly argparse error."""
    ec, out, err = _run(["workspace", "w", "rule", "add", "--host", "x.example.com"])
    assert ec != 0


def test_logs_structured_records_are_forgery_resistant():
    """The structured `credproxy {json}` stream can't be forged from a rule-error
    message: the proxy JSON-encodes the (workspace-influenced) message, so it is an
    escaped VALUE on ONE physical line -- it parses as kind=rule-error, never as a
    second audit line."""
    import json
    from credproxy_cli.porcelain.cli import _parse_credproxy_line
    # genuine audit record
    assert _parse_credproxy_line(
        'credproxy {"ts":"t","kind":"audit","event":"inject","binding":"gh"}\n') \
        == {"ts": "t", "kind": "audit", "event": "inject", "binding": "gh"}
    # a rule error whose message tries to forge an audit event -- as the proxy
    # actually emits it: json.dumps escapes the newline, so it stays ONE line.
    forged = 'boom\ncredproxy {"kind":"audit","event":"inject","binding":"forged"}'
    line = "credproxy " + json.dumps(
        {"ts": "t", "kind": "rule-error", "rule": "x", "error": forged})
    assert "\n" not in line                        # newline escaped -> single line
    assert _parse_credproxy_line(line + "\n")["kind"] == "rule-error"   # not audit
    # non-prefixed / non-object / no-kind lines are rejected
    assert _parse_credproxy_line(
        '[rule] x failed: credproxy {"kind":"audit"}\n') is None
    assert _parse_credproxy_line('credproxy "not an object"\n') is None
    assert _parse_credproxy_line('credproxy {"no":"kind"}\n') is None


def test_format_record_handles_every_kind():
    """The `logs` reformatter renders each record kind and never crashes on a
    missing key or an unknown/future kind."""
    from credproxy_cli.porcelain.cli import _format_record
    assert "inject" in _format_record(
        {"ts": "t", "kind": "audit", "event": "inject", "binding": "gh",
         "host": "h", "outcome": "injected"})
    assert "rewrite:rw" in _format_record(
        {"ts": "t", "kind": "http", "method": "GET", "host": "h", "path": "/p",
         "marks": ["rewrite:rw"]})
    assert "intercept" in _format_record(
        {"ts": "t", "kind": "sni", "sni": "h", "decision": "intercept"})
    assert "boom" in _format_record(
        {"ts": "t", "kind": "rule-error", "rule": "x", "error": "boom"})
    assert _format_record({"kind": "http"})              # missing keys: no crash
    assert "weird" in _format_record({"ts": "t", "kind": "weird", "foo": "bar"})


def test_rule_test_json_envelope_offline_and_live(capsys):
    """Offline and --live `rule test --json` share one envelope (method/url/live/
    matches), so a consumer parses one shape; --live just adds intercepted/phase."""
    import json
    from credproxy_cli.porcelain.render import JsonRenderer
    r = JsonRenderer()
    r.rule_test("GET", "https://h/x", [{"name": "a", "action": "block"}])
    off = json.loads(capsys.readouterr().out)
    assert off == {"method": "GET", "url": "https://h/x", "live": False,
                   "matches": [{"name": "a", "action": "block"}]}
    r.rule_test_live("GET", "https://h/x",
                     {"intercepted": True, "host": "h", "path": "/x",
                      "matches": [{"name": "a", "phase": "response"}]})
    live = json.loads(capsys.readouterr().out)
    assert live["live"] is True and live["intercepted"] is True
    assert live["method"] == "GET" and live["url"] == "https://h/x"
    assert live["matches"][0]["phase"] == "response"
