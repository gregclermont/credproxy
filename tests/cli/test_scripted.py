"""Tests for the scripted-injector CLI path: the scripts
registry, scheme="script" injector parsing, and the wire shape (pushed source).
"""
from __future__ import annotations

import textwrap

import pytest


def _write_injector(name: str, body: str):
    from credproxy_cli.core.paths import injectors_config_dir
    d = injectors_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.toml").write_text(textwrap.dedent(body))


def _write_script(name: str, body: str):
    from credproxy_cli.core.paths import scripts_config_dir
    d = scripts_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.star").write_text(body)


# ---- scripts registry --------------------------------------------------------


def test_find_builtin_scripts(xdg):
    from credproxy_cli.core.scripts import find_script

    for name in ("bearer", "basic", "body"):
        s = find_script(name)
        assert s.source_origin == "builtin"
        assert "def on_request" in s.source


def test_user_script_shadows_builtin(xdg):
    _write_script("bearer", "def on_request():\n    return True\n")
    from credproxy_cli.core.scripts import find_script

    s = find_script("bearer")
    assert s.source_origin == "user"


def test_find_script_missing(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.scripts import find_script

    with pytest.raises(InjectorError, match="not found"):
        find_script("nope_zzz")


def test_list_scripts_includes_builtin(xdg):
    from credproxy_cli.core.scripts import list_scripts

    names = [s.name for s in list_scripts()]
    assert {"bearer", "basic", "body", "ovh", "jwt-bearer"} <= set(names)


# ---- builtin scripted injectors (ovh, jwt-bearer) parse + resolve ------------


def test_builtin_ovh_injector(xdg):
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.scripts import find_script

    inj = find_injector("ovh")
    assert inj.scheme == "script" and inj.script == "ovh"
    assert inj.spec.family == "sign"
    assert inj.spec.slots == ("app_key", "app_secret", "consumer_key")
    assert "def on_request" in find_script("ovh").source


def test_builtin_jwt_bearer_injector(xdg):
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.scripts import find_script

    inj = find_injector("jwt-bearer")
    assert inj.scheme == "script" and inj.script == "jwt-bearer"
    assert inj.spec.family == "sign"
    assert inj.spec.slots == ("private_key",)
    assert inj.params["iss"] and inj.params["ttl"]   # [params] parsed
    assert inj.api == 1
    assert "jwt_encode_sign" in find_script("jwt-bearer").source


# ---- scripted injector parsing -----------------------------------------------


def test_scripted_injector_parses(xdg):
    _write_injector("custom", """
        scheme = "script"
        script = "bearer"
        family = "substitute"
        slots  = ["value"]
        [params]
        header = "X-Api-Key"
    """)
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("custom")
    assert inj.scheme == "script"
    assert inj.script == "bearer"
    assert inj.spec.family == "substitute"
    assert inj.spec.slots == ("value",)
    assert inj.spec.uses_placeholder is True
    assert inj.params["header"] == "X-Api-Key"


def test_scripted_sign_family(xdg):
    _write_injector("signer", """
        scheme = "script"
        script = "ovh"
        family = "sign"
        slots  = ["app_secret", "consumer_key"]
    """)
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("signer")
    assert inj.spec.family == "sign"
    assert inj.spec.slots == ("app_secret", "consumer_key")
    assert inj.spec.uses_placeholder is False


def test_scripted_missing_script_field(xdg):
    _write_injector("bad", 'scheme = "script"\nfamily = "substitute"\nslots = ["value"]\n')
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="needs `script`"):
        find_injector("bad")


def test_scripted_bad_family(xdg):
    _write_injector("bad", 'scheme = "script"\nscript = "x"\nfamily = "bogus"\nslots = ["value"]\n')
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="family must be"):
        find_injector("bad")


def test_scripted_empty_slots(xdg):
    _write_injector("bad", 'scheme = "script"\nscript = "x"\nfamily = "sign"\nslots = []\n')
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="slots must be"):
        find_injector("bad")


def test_scripted_api_version_parsed(xdg):
    _write_injector("v2signer", """
        scheme = "script"
        script = "ovh"
        api    = 2
        family = "sign"
        slots  = ["app_secret"]
    """)
    from credproxy_cli.core.injectors import find_injector

    assert find_injector("v2signer").api == 2


def test_scripted_default_api_is_one(xdg):
    _write_injector("noapi", """
        scheme = "script"
        script = "bearer"
        family = "substitute"
        slots  = ["value"]
    """)
    from credproxy_cli.core.injectors import find_injector

    assert find_injector("noapi").api == 1


def test_scripted_bad_api_rejected(xdg):
    _write_injector("badapi",
                    'scheme="script"\nscript="x"\napi="nope"\nfamily="sign"\nslots=["value"]\n')
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="`api` must be an integer"):
        find_injector("badapi")


# ---- wire shape (pushed source) ----------------------------------------------


def test_wire_config_scripted_pushes_source(xdg, workspaces_dir):
    _write_injector("custom", """
        scheme = "script"
        script = "bearer"
        family = "substitute"
        slots  = ["value"]
        [params]
        header = "Authorization"
    """)
    from credproxy_cli.core.bindings import Binding, wire_config

    b = Binding(name="b", injector="custom", provider="env", secret="TOK",
                hosts=("api.example.com",), placeholder="tok_xxxxxxxxxxxx", env=None)
    wire = wire_config([b], fetch_many=lambda p, refs: {r: "REAL" for r in refs})
    e = wire["bindings"][0]
    assert e["scheme"] == "script"
    assert e["script"] == "bearer"
    assert "def on_request" in e["script_source"]   # the pushed .star body
    assert e["api"] == 1
    assert e["family"] == "substitute"
    assert e["slots"] == ["value"]
    assert e["location_kind"] == "header"
    assert e["secret"] == {"value": "REAL"}
    assert e["placeholder"] == "tok_xxxxxxxxxxxx"


def test_validate_scripted_slot_mismatch(xdg, workspaces_dir):
    _write_injector("signer", """
        scheme = "script"
        script = "ovh"
        family = "sign"
        slots  = ["app_secret", "consumer_key"]
    """)
    from credproxy_cli.core.bindings import Binding, validate
    from credproxy_cli.core.errors import ConfigError

    # single-slot secret for a two-slot scripted scheme -> rejected
    b = Binding(name="b", injector="signer", provider="env", secret="ONLY_ONE",
                hosts=("h",), placeholder=None, env=None)
    with pytest.raises(ConfigError, match="needs secret slot"):
        validate([b], "test")
