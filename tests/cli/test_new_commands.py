"""Tests for the `current` meta command and ad-hoc `binding test` mode.

Both were added to close design-v2 naming-reference gaps: `current` prints
the default workspace, and `binding test --provider/--secret` exercises a
definition before it is bound (no workspace required). The bundled `env`
provider is used as the standalone subject under test.
"""
from __future__ import annotations

import json

from test_porcelain import _run, _run_loose


# ---- current -----------------------------------------------------------------


def test_current_no_default(xdg, workspaces_dir):
    ec, out, err = _run(["current"])
    assert ec == 0
    assert "no default" in out.lower()


def test_current_no_default_json(xdg, workspaces_dir):
    ec, out, err = _run(["--json", "current"])
    assert ec == 0
    assert json.loads(out) == {"default": None}


def test_current_reports_pointer(xdg, workspaces_dir):
    (workspaces_dir / "proj.toml").write_text('image = "x"\n')
    from credproxy_cli.core.pointer import set_default
    from credproxy_cli.core.workspace import Workspace
    set_default(Workspace("proj"))

    ec, out, err = _run(["current"])
    assert ec == 0
    assert out.strip() == "proj"

    ec, out, err = _run(["--json", "current"])
    assert json.loads(out) == {"default": "proj"}


# ---- ad-hoc binding test -----------------------------------------------------


def test_adhoc_test_ok(xdg, monkeypatch):
    """`binding test --provider env --secret VAR` with the var set -> ok,
    reports value length only, no workspace needed."""
    monkeypatch.setenv("CP_ADHOC_SECRET", "hunter2")
    ec, out, err = _run(
        ["workspace", "binding", "test", "--provider", "env",
         "--secret", "CP_ADHOC_SECRET"]
    )
    assert ec == 0
    assert "ok" in out
    assert "7" in out          # len("hunter2")
    assert "hunter2" not in out  # value itself never printed


def test_adhoc_test_with_injector_validates(xdg, monkeypatch):
    monkeypatch.setenv("CP_ADHOC_SECRET", "abc")
    ec, out, err = _run(
        ["workspace", "binding", "test", "--injector", "github",
         "--provider", "env", "--secret", "CP_ADHOC_SECRET"]
    )
    assert ec == 0
    assert "github-env" in out


def test_adhoc_test_missing_secret_fails(xdg, monkeypatch):
    monkeypatch.delenv("CP_NOPE", raising=False)
    ec, out, err = _run(
        ["workspace", "binding", "test", "--provider", "env", "--secret", "CP_NOPE"]
    )
    assert ec != 0


def test_adhoc_test_unknown_provider_fails(xdg):
    ec, out, err = _run(
        ["workspace", "binding", "test", "--provider", "nosuch", "--secret", "X"]
    )
    assert ec != 0
    assert "not found" in err.lower()


def test_adhoc_requires_secret(xdg):
    ec, out, err = _run(["workspace", "binding", "test", "--provider", "env"])
    assert ec != 0
    assert "--secret" in err


def test_adhoc_rejects_name_with_flags(xdg, ws_factory):
    ws_factory("proj")
    ec, out, err = _run(
        ["workspace", "proj", "binding", "test", "somebinding",
         "--provider", "env", "--secret", "X"]
    )
    assert ec != 0
    assert "cannot combine" in err.lower()


def test_adhoc_test_json_shape(xdg, monkeypatch):
    monkeypatch.setenv("CP_ADHOC_SECRET", "abcd")
    ec, out, err = _run(
        ["--json", "workspace", "binding", "test", "--provider", "env",
         "--secret", "CP_ADHOC_SECRET"]
    )
    assert ec == 0
    rows = json.loads(out)
    assert isinstance(rows, list) and len(rows) == 1
    assert rows[0]["ok"] is True
    assert rows[0]["value_len"] == 4
    assert "value" not in rows[0]  # never the secret itself


def test_adhoc_test_loose(xdg, monkeypatch):
    """`credp binding test --provider ... --secret ...` resolves no default
    workspace -- ad-hoc bypasses workspace resolution entirely."""
    monkeypatch.setenv("CP_ADHOC_SECRET", "x")
    ec, out, err = _run_loose(
        ["binding", "test", "--provider", "env", "--secret", "CP_ADHOC_SECRET"]
    )
    assert ec == 0
    assert "ok" in out
