"""Tests for the scripted-injector (escape-hatch) usability fixes:

  - `injector scaffold NAME --script` emits a VALID manifest + .star pair (the
    round-trip: it parses, resolves, and binds), so the escape hatch is
    authorable instead of reverse-engineered.
  - `injector list` shows a SCHEME column marking scripted injectors.
  - the `unknown scheme` error points at scheme="script".
  - a binding whose injector names a missing .star is rejected host-side
    (add + validate), and `binding test` annotates a resolved script instead of
    silently saying ok.
  - `injector check NAME` validates host-side (manifest + script resolves).

The `--compile` docker path is exercised live against the proxy image, not here
(unit tests have no image); this module covers everything host-side.
"""
from __future__ import annotations

import json

import pytest

from test_porcelain import _run


# ---- scaffold --script round-trip --------------------------------------------


@pytest.mark.parametrize("family,slot,marker", [
    ("sign", "key", "X-My-Signature"),
    ("substitute", "value", "placeholder()"),
])
def test_scaffold_script_roundtrip(family, slot, marker, xdg):
    """Scaffold a scripted injector, then prove the emitted definition is real:
    it resolves, lists as a script, and binds with the declared slot."""
    from credproxy_cli.core.paths import (
        injectors_config_dir, scripts_config_dir,
    )
    code, out, err = _run(["injector", "scaffold", "sig", "--script", family])
    assert code == 0

    manifest = injectors_config_dir() / "sig.toml"
    script = scripts_config_dir() / "sig.star"
    assert manifest.is_file() and script.is_file()
    assert 'scheme        = "script"' in manifest.read_text()
    assert f'family        = "{family}"' in manifest.read_text()
    assert marker in script.read_text()
    # The primitive-API reference is carried inline in the script.
    assert "Primitive API" in script.read_text() and "req_set_header" in script.read_text()

    # The emitted injector parses + resolves its script (no reverse-engineering).
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.scripts import find_script
    inj = find_injector("sig")
    assert inj.scheme == "script" and inj.script == "sig"
    assert inj.spec.family == family and inj.spec.slots == (slot,)
    find_script("sig")  # resolves


def test_scaffold_script_refuses_overwrite(xdg):
    assert _run(["injector", "scaffold", "dup", "--script", "sign"])[0] == 0
    code, out, err = _run(["injector", "scaffold", "dup", "--script", "sign"])
    assert code == 1 and "already exists" in (out + err)


def test_scaffold_script_bad_family(xdg):
    code, out, err = _run(["injector", "scaffold", "x", "--script", "bogus"])
    # "bogus" is not a family token, so it's treated as a second positional ->
    # usage error; either way it must not scaffold.
    assert code == 1


def test_scaffold_script_on_provider_rejected(xdg):
    code, out, err = _run(["provider", "scaffold", "x", "--script"])
    assert code == 1 and "only valid for" in (out + err)


# ---- injector list SCHEME column ---------------------------------------------


def test_injector_list_shows_scheme_column(xdg):
    _run(["injector", "scaffold", "sig", "--script", "sign"])
    code, out, err = _run(["injector", "list"])
    assert code == 0
    blob = out + err
    assert "SCHEME" in blob
    # bundled bearer is a built-in; our scaffolded one is a script.
    assert "bearer" in blob
    assert "script:sign" in blob


def test_injector_list_json_has_scheme():
    code, out, err = _run(["--json", "injector", "list"])
    assert code == 0
    rows = json.loads(out)
    bearer = next(r for r in rows if r["name"] == "bearer")
    assert bearer["scheme"] == "bearer"
    ovh = next(r for r in rows if r["name"] == "ovh")
    assert ovh["scheme"].startswith("script:")


# ---- unknown-scheme error points at script -----------------------------------


def test_unknown_scheme_error_mentions_script(xdg):
    from credproxy_cli.core.paths import injectors_config_dir
    d = injectors_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "weird.toml").write_text('scheme = "nope"\n')
    code, out, err = _run(["injector", "list"])
    assert code == 1
    assert 'scheme="script"' in (out + err)


# ---- missing-script guard ----------------------------------------------------


def _ws_with_script_injector(xdg, script_name):
    """Create a workspace + a scripted injector whose `script` points at
    `script_name`. Returns nothing; uses the CLI so paths come from XDG."""
    from credproxy_cli.core.paths import injectors_config_dir
    d = injectors_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "sig.toml").write_text(
        'scheme = "script"\n'
        f'script = "{script_name}"\n'
        'api = 1\nfamily = "sign"\nslots = ["key"]\nlocation_kind = "header"\n'
    )
    assert _run(["workspace", "create", "w"])[0] == 0


def test_binding_add_rejects_missing_script(xdg):
    _ws_with_script_injector(xdg, "does-not-exist")
    code, out, err = _run(["workspace", "w", "binding", "add", "--injector", "sig",
                           "--provider", "env", "--secret", "key=HK",
                           "--host", "api.example.com"])
    assert code == 1
    assert "not found" in (out + err) and "does-not-exist" in (out + err)


def test_binding_test_notes_resolved_script(xdg, monkeypatch):
    # Author a real script so the binding is valid, then test it.
    assert _run(["injector", "scaffold", "sig", "--script", "sign"])[0] == 0
    assert _run(["workspace", "create", "w"])[0] == 0
    assert _run(["workspace", "w", "binding", "add", "--injector", "sig",
                 "--provider", "env", "--secret", "key=HK",
                 "--host", "api.example.com"])[0] == 0
    monkeypatch.setenv("HK", "topsecret")
    code, out, err = _run(["workspace", "w", "binding", "test"])
    assert code == 0
    assert "script 'sig' resolved" in (out + err)


# ---- injector check (host-side) ----------------------------------------------


def test_injector_check_scripted_ok(xdg):
    assert _run(["injector", "scaffold", "sig", "--script", "sign"])[0] == 0
    code, out, err = _run(["injector", "check", "sig"])
    assert code == 0
    blob = out + err
    assert "manifest ok" in blob and "resolves" in blob


def test_injector_check_builtin(xdg):
    code, out, err = _run(["injector", "check", "bearer"])
    assert code == 0
    assert "built-in" in (out + err)


def test_injector_check_missing_script(xdg):
    from credproxy_cli.core.paths import injectors_config_dir
    d = injectors_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "sig.toml").write_text(
        'scheme = "script"\nscript = "gone"\napi = 1\n'
        'family = "sign"\nslots = ["key"]\nlocation_kind = "header"\n'
    )
    code, out, err = _run(["injector", "check", "sig"])
    assert code == 1
    assert "not found" in (out + err)
