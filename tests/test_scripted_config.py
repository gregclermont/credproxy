"""Proxy-side dispatch for scripted injection schemes.

config.load_resolved must accept a pushed `scheme: "script"` binding, compile
the pushed `.star` source into a ScriptedScheme, validate it uniformly with the
built-ins (slots, placeholder, wire-location), and run it.
"""
from pathlib import Path

import pytest
from mitmproxy.test import tflow, tutils

import config
import schemes

BEARER_STAR = (Path(__file__).resolve().parents[1]
               / "cli" / "credproxy_cli" / "builtin" / "scripts" / "bearer.star").read_text()


def _script_entry(**over):
    e = {
        "name": "scripted", "hosts": ["api.example.com"],
        "scheme": "script", "script": "bearer", "script_source": BEARER_STAR,
        "family": "substitute", "slots": ["value"], "location_kind": "header",
        "header_default": "Authorization",
        "params": {"header": "Authorization"},
        "secret": {"value": "REALSECRET"}, "placeholder": "tok_PH",
    }
    e.update(over)
    return e


def test_scripted_scheme_loads_and_runs():
    creds = config.load_resolved({"bindings": [_script_entry()]})
    assert creds.intercept_hosts() == {"api.example.com"}
    [t] = creds.transforms_for("api.example.com")
    assert t.scheme.name == "bearer"           # the .star's declared name
    assert t.scheme.family == "substitute"
    assert t.placeholder == "tok_PH"

    # The compiled script actually injects.
    req = tutils.treq(host="api.example.com")
    req.headers.clear()
    req.headers["Authorization"] = "Bearer tok_PH"
    flow = tflow.tflow(req=req)
    ctx = schemes.RequestCtx(req, t.secrets, t.params, t.placeholder)
    assert t.scheme.on_request(ctx) is True
    assert req.headers["Authorization"] == "Bearer REALSECRET"


def test_scripted_scheme_location_collision_with_bearer():
    """A scripted header scheme collides with a built-in bearer on the same
    header + host when they share a placeholder (uniform wire-location
    detection); distinct placeholders would disambiguate them."""
    with pytest.raises(config.ConfigError, match="both write header"):
        config.load_resolved({"bindings": [
            _script_entry(name="s1", placeholder="tok_x"),
            {"name": "s2", "hosts": ["api.example.com"], "scheme": "bearer",
             "params": {"header": "Authorization"}, "placeholder": "tok_x",
             "secret": {"value": "r"}},
        ]})


def test_scripted_missing_source_rejected():
    e = _script_entry()
    del e["script_source"]
    with pytest.raises(config.ConfigError, match="needs a non-empty 'script_source'"):
        config.load_resolved({"bindings": [e]})


def test_scripted_bad_family_rejected():
    with pytest.raises(config.ConfigError, match="family must be"):
        config.load_resolved({"bindings": [_script_entry(family="bogus")]})


def test_scripted_slot_mismatch_rejected():
    """The declared slots must match the pushed secret (uniform with built-ins)."""
    with pytest.raises(config.ConfigError, match="needs secret slot"):
        config.load_resolved({"bindings": [
            _script_entry(slots=["access_key_id", "secret_access_key"])
        ]})


def test_scripted_compile_error_rejected():
    with pytest.raises(config.ConfigError, match="failed to compile"):
        config.load_resolved({"bindings": [
            _script_entry(script_source="def on_request():\n    this is not valid\n")
        ]})


def test_scripted_unsupported_api_rejected():
    """A script declaring an api version this proxy doesn't implement is
    rejected before it runs (the forward-compat seam)."""
    with pytest.raises(config.ConfigError, match="unsupported by this proxy"):
        config.load_resolved({"bindings": [_script_entry(api=99)]})


def test_scripted_bad_api_type_rejected():
    with pytest.raises(config.ConfigError, match="api must be an integer"):
        config.load_resolved({"bindings": [_script_entry(api="two")]})


def test_scripted_sign_family_needs_no_placeholder():
    """A sign-family scripted scheme has no placeholder, like sigv4."""
    e = _script_entry(family="sign")
    del e["placeholder"]
    creds = config.load_resolved({"bindings": [e]})
    [t] = creds.transforms_for("api.example.com")
    assert t.placeholder is None
    assert t.scheme.family == "sign"
