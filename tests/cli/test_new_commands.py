"""Tests for the `current` meta command and ad-hoc `binding test` mode.

Both were added to close naming-reference gaps: `current` prints
the default workspace, and `binding test --provider/--secret` exercises a
definition before it is bound (no workspace required). The builtin `env`
provider is used as the standalone subject under test.
"""
from __future__ import annotations

import json

import pytest

from test_porcelain import _run, _run_loose


# ---- _parse_secret_args ------------------------------------------------------


def test_parse_secret_single_bare():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["GITHUB_TOKEN"]) == "GITHUB_TOKEN"


def test_parse_secret_single_bare_with_equals():
    """A lone ref containing '=' stays a bare single-slot ref (not split)."""
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["op://v/i?ver=2"]) == "op://v/i?ver=2"


def test_parse_secret_none():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(None) is None
    assert _parse_secret_args([]) is None


def test_parse_secret_multi_slot():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["access_key_id=A", "secret_access_key=B"]) == {
        "access_key_id": "A", "secret_access_key": "B"}


def test_parse_secret_multi_slot_ref_with_equals():
    """REF is split on the FIRST '=', so a ref containing '=' survives."""
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["k=op://v/i?x=1", "j=B"]) == {
        "k": "op://v/i?x=1", "j": "B"}


def test_parse_secret_multi_requires_slot_eq():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    with pytest.raises(SystemExit):
        _parse_secret_args(["bare1", "bare2"])


def test_parse_secret_multi_duplicate_slot():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    with pytest.raises(SystemExit):
        _parse_secret_args(["k=A", "k=B"])


# ---- single named slot (#6): `--secret SLOT=REF` for one non-`value` slot ----


def test_parse_secret_single_named_slot():
    """A lone SLOT=REF whose SLOT is a declared slot -> that named slot."""
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["private_key=PK_REF"], ("private_key",)) == {
        "private_key": "PK_REF"}


def test_parse_secret_single_named_slot_ref_with_equals():
    """REF after the slot name keeps any further '=' (split on the first only)."""
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["private_key=op://v/i?ver=2"], ("private_key",)) == {
        "private_key": "op://v/i?ver=2"}


def test_parse_secret_single_unknown_slot_stays_bare_ref():
    """A lone ref containing '=' whose prefix is NOT a declared slot stays a bare
    ref -- the disambiguation that keeps vault-path refs working."""
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["op://v/i?ver=2"], ("value",)) == "op://v/i?ver=2"


def test_parse_secret_single_value_slot_explicit():
    from credproxy_cli.porcelain.cli import _parse_secret_args
    assert _parse_secret_args(["value=REF"], ("value",)) == {"value": "REF"}


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
        ["workspace", "binding", "test", "--injector", "bearer",
         "--provider", "env", "--secret", "CP_ADHOC_SECRET"]
    )
    assert ec == 0
    assert "bearer-env" in out


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
