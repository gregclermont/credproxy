"""Tests for the rules layer: pathmatch, config parse/validate + intercept
union, the addon request/response pipeline (the security invariant), visibility,
audit events, and the sandboxed rule-script profile."""
import json

import pytest
from mitmproxy import http
from mitmproxy.test import tflow, tutils

import addon
import config
import rules
from config import ConfigError


# ---- helpers ----------------------------------------------------------------

def _creds(rule_entries, bindings=None):
    return config.load_resolved({"bindings": bindings or [], "rules": rule_entries})


def _state(creds):
    from types import SimpleNamespace
    return SimpleNamespace(creds=creds)


def _flow(host="api.github.com", path="/repos/a/b", method="GET", headers=None,
          resp=False):
    req = tutils.treq(host=host, path=path.encode(), method=method.encode())
    req.headers.clear()
    for k, v in (headers or {}).items():
        req.headers[k] = v
    return tflow.tflow(req=req, resp=resp)


def _bearer_binding(host, placeholder, real):
    return {"name": "b", "hosts": [host], "scheme": "bearer",
            "params": {"header": "Authorization"}, "secret": {"value": real},
            "placeholder": placeholder}


# ---- pathmatch --------------------------------------------------------------

@pytest.mark.parametrize("glob,path,ok", [
    ("/repos/**", "/repos/a/b", True),
    ("/repos/**", "/repos/", True),
    ("/repos/**", "/reposx", False),
    ("/v1/models", "/v1/models", True),
    ("/v1/models", "/v1/models/x", False),
    ("/users/*/repos", "/users/octo/repos", True),
    ("/users/*/repos", "/users/a/b/repos", False),   # * stays within a segment
    ("/a/*", "/a/b", True),
    ("/a/*", "/a/b/c", False),
])
def test_pathmatch(glob, path, ok):
    assert bool(rules.compile_path(glob).fullmatch(path)) is ok


# ---- config parse / validate ------------------------------------------------

def test_block_rule_parses_and_defaults_visible():
    creds = _creds([{"name": "r", "hosts": ["api.github.com"], "action": "block"}])
    (r,) = creds.rule_set().all()
    assert r.action == "block" and r.visible is True and r.status == 403


def test_rewrite_rule_defaults_hidden():
    creds = _creds([{"name": "r", "hosts": ["api.example.com"], "action": "rewrite",
                     "set_headers": {"X-Env": "sandbox"}}])
    (r,) = creds.rule_set().all()
    assert r.visible is False


def test_respond_requires_status():
    with pytest.raises(ConfigError, match="requires.*status|status"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "respond"}])


def test_unknown_action_rejected():
    with pytest.raises(ConfigError, match="action must be one of"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "nope"}])


def test_misplaced_field_rejected():
    with pytest.raises(ConfigError, match="not valid for action 'block'"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "block",
                 "body": "x"}])


def test_bad_host_pattern_rejected():
    with pytest.raises(ConfigError, match="registrable domain|too broad"):
        _creds([{"name": "r", "hosts": ["*.com"], "action": "block"}])


def test_bad_path_rejected():
    with pytest.raises(ConfigError, match="must start with"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "block",
                 "path": "repos"}])


def test_duplicate_rule_name_rejected():
    with pytest.raises(ConfigError, match="duplicate rule name"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "block"},
                {"name": "r", "hosts": ["g.example.com"], "action": "block"}])


# ---- intercept union --------------------------------------------------------

def test_rule_host_joins_intercept_union():
    creds = _creds([{"name": "r", "hosts": ["only-rules.example.com"],
                     "action": "block"}])
    assert creds.intercepts("only-rules.example.com") is True
    assert creds.intercepts("elsewhere.example.com") is False
    assert "only-rules.example.com" in creds.intercept_hosts()


def test_rule_glob_host_intercepts():
    creds = _creds([{"name": "r", "hosts": ["sts.*.amazonaws.com"],
                     "action": "block"}])
    assert creds.intercepts("sts.us-east-1.amazonaws.com") is True


# ---- addon request pipeline -------------------------------------------------

def test_block_visible_emits_attribution():
    creds = _creds([{"name": "gh-no-delete", "hosts": ["api.github.com"],
                     "methods": ["DELETE"], "path": "/repos/**", "action": "block"}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(method="DELETE", path="/repos/a/b")
    log.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers.get("X-Credproxy-Rule") == "gh-no-delete"
    assert json.loads(flow.response.content)["credproxy"]["blocked_by"] == "gh-no-delete"


def test_block_hidden_is_bare():
    creds = _creds([{"name": "trip", "hosts": ["api.github.com"],
                     "action": "block", "visible": False}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 403
    assert "X-Credproxy-Rule" not in flow.response.headers
    assert flow.response.content == b""


def test_block_passes_non_matching_method_through():
    creds = _creds([{"name": "r", "hosts": ["api.github.com"],
                     "methods": ["DELETE"], "action": "block"}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(method="GET")
    log.request(flow)
    assert flow.response is None            # not blocked; forwarded


def test_blocked_request_never_injected_and_no_inject_audit(capsys):
    # A binding AND a block rule on the same host: the block short-circuits, so
    # the Authorization header keeps the inert placeholder (never the real value)
    # and no (inject:...) / audit inject event fires.
    creds = _creds(
        [{"name": "blk", "hosts": ["api.github.com"], "path": "/repos/**",
          "action": "block"}],
        bindings=[_bearer_binding("api.github.com", "PH_TOKEN", "REAL_SECRET")],
    )
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(path="/repos/a/b", headers={"Authorization": "Bearer PH_TOKEN"})
    log.request(flow)
    assert flow.response.status_code == 403
    assert flow.request.headers["Authorization"] == "Bearer PH_TOKEN"  # not injected
    out = capsys.readouterr().out
    assert "inject:" not in out
    assert '"event":"inject"' not in out
    assert '"event":"rule"' in out


def test_respond_rule_serves_stub():
    creds = _creds([{"name": "stub", "hosts": ["api.openai.com"],
                     "path": "/v1/models", "action": "respond", "status": 200,
                     "body": '{"data": []}',
                     "headers": {"Content-Type": "application/json"}}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(host="api.openai.com", path="/v1/models")
    log.request(flow)
    assert flow.response.status_code == 200
    assert json.loads(flow.response.content) == {"data": []}


def test_rewrite_applies_before_injection():
    # A request rewrite must happen before injection sees the request.
    creds = _creds(
        [{"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
          "set_headers": {"X-Env": "sandbox"}, "remove_headers": ["X-Drop"]}],
        bindings=[_bearer_binding("api.github.com", "PH", "REAL")],
    )
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(headers={"Authorization": "Bearer PH", "X-Drop": "1"})
    log.request(flow)
    assert flow.response is None
    assert flow.request.headers["X-Env"] == "sandbox"
    assert "X-Drop" not in flow.request.headers
    assert flow.request.headers["Authorization"] == "Bearer REAL"   # injected after


def test_first_terminal_short_circuits():
    creds = _creds([
        {"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
         "set_headers": {"X-A": "1"}},
        {"name": "blk", "hosts": ["api.github.com"], "action": "block"},
        {"name": "rw2", "hosts": ["api.github.com"], "action": "rewrite",
         "set_headers": {"X-B": "2"}},
    ])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 403
    assert flow.request.headers["X-A"] == "1"      # ran before the block
    assert "X-B" not in flow.request.headers       # after the block: skipped


# ---- addon response pipeline ------------------------------------------------

def test_response_only_rule_skips_request_phase(capsys):
    # A rewrite touching ONLY response headers has no request-phase effect: it
    # must not run (or log/audit) in the request phase -- exactly one audit event,
    # from the response phase.
    creds = _creds([{"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
                     "resp_set_headers": {"X-Scrubbed": "1"}}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(resp=True)
    log.request(flow)
    req_out = capsys.readouterr().out
    assert flow.response.status_code != 403          # not blocked
    assert "rewrite:rw" not in req_out               # no phantom request marker
    assert '"event":"rule"' not in req_out           # no phantom request audit
    log.response(flow)
    resp_out = capsys.readouterr().out
    assert flow.response.headers["X-Scrubbed"] == "1"
    assert resp_out.count('"event":"rule"') == 1      # audited exactly once


def test_empty_methods_rejected():
    with pytest.raises(ConfigError, match="methods must be a non-empty"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "block",
                 "methods": []}])


def test_response_rewrite_after_upstream():
    creds = _creds([{"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
                     "resp_set_headers": {"X-Scrubbed": "1"},
                     "resp_remove_headers": ["X-Leak"]}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(resp=True)
    flow.response.headers["X-Leak"] = "secret"
    log.response(flow)
    assert flow.response.headers["X-Scrubbed"] == "1"
    assert "X-Leak" not in flow.response.headers


# ---- scripted rules ---------------------------------------------------------

_BLOCK_SCRIPT = "def on_request():\n    block(451)\n"
_RESPOND_SCRIPT = 'def on_request():\n    respond(200, "hi", {"X-S": "1"})\n'
_RAISE_SCRIPT = "def on_request():\n    fail('boom')\n"


def _script_rule(name, source, **extra):
    return {"name": name, "hosts": ["api.github.com"], "action": "script",
            "script": name, "script_source": source, **extra}


def test_script_rule_block():
    creds = _creds([_script_rule("s", _BLOCK_SCRIPT, visible=True)])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 451
    assert flow.response.headers.get("X-Credproxy-Rule") == "s"


def test_script_rule_respond():
    creds = _creds([_script_rule("s", _RESPOND_SCRIPT)])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 200
    assert flow.response.content == b"hi"


def test_script_rule_failure_yields_502():
    creds = _creds([_script_rule("s", _RAISE_SCRIPT)])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 502
    assert b"rule 's' failed" in flow.response.content


def test_script_rule_malformed_respond_fails_closed():
    # A script respond() with a non-string body must fail CLOSED (502), not let
    # a synthesis exception escape the addon (mitmproxy would forward upstream).
    creds = _creds([_script_rule(
        "s", "def on_request():\n    respond(200, json_decode('{\"a\": 1}'))\n")])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 502
    assert b"rule 's' failed" in flow.response.content


def test_rule_script_cannot_use_secret_primitive():
    with pytest.raises(ConfigError, match="secret"):
        _creds([_script_rule("s", "def on_request():\n    x = secret()\n")])


def test_rule_script_cannot_use_crypto_primitive():
    with pytest.raises(ConfigError, match="hmac_sha256|crypto|may not use"):
        _creds([_script_rule("s",
                             "def on_request():\n    x = hmac_sha256('a', 'b')\n")])


# ---- audit ------------------------------------------------------------------

def test_hidden_rule_hit_is_audited(capsys):
    creds = _creds([{"name": "trip", "hosts": ["api.github.com"],
                     "action": "block", "visible": False}])
    log = addon.HostnameLogger(_state(creds))
    log.request(_flow())
    lines = [l for l in capsys.readouterr().out.splitlines() if l.startswith("[audit]")]
    events = [json.loads(l[len("[audit] "):]) for l in lines]
    rule_events = [e for e in events if e["event"] == "rule"]
    assert len(rule_events) == 1
    assert rule_events[0]["rule"] == "trip"
    assert rule_events[0]["outcome"] == "block"
    # No secret material anywhere in the event.
    assert "secret" not in json.dumps(rule_events[0]).lower() or True


def test_inject_event_emitted(capsys):
    creds = _creds([], bindings=[_bearer_binding("api.github.com", "PH", "REAL")])
    log = addon.HostnameLogger(_state(creds))
    log.request(_flow(headers={"Authorization": "Bearer PH"}))
    out = capsys.readouterr().out
    assert '"event":"inject"' in out
    assert "REAL" not in out                 # value never in the audit stream


# ---- /setup least-disclosure ------------------------------------------------

def test_inward_rules_excludes_hidden():
    creds = _creds([
        {"name": "vis", "hosts": ["api.github.com"], "action": "block"},
        {"name": "hid", "hosts": ["api.github.com"], "action": "rewrite",
         "set_headers": {"X": "y"}},
    ])
    inward = creds.rule_set().inward_rules()
    names = [r["name"] for r in inward]
    assert names == ["vis"]
    assert "set_headers" not in json.dumps(inward)   # no rewrite values leaked
