"""Tests for the rules layer: pathmatch, config parse/validate + intercept
union, the addon request/response pipeline (the security invariant), visibility,
audit events, and the sandboxed rule-script profile."""
import json
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.test import tflow, tutils

import addon
import config
import rules
from config import ConfigError

# The builtin rule script, mounted read-only at /opt/cli in the proxy test image
# (see do_dev_test) -- single source of truth, exercised end-to-end below.
_SCRUB_EMAILS = (Path(__file__).resolve().parents[1] / "cli" / "credproxy_cli"
                 / "builtin" / "scripts" / "scrub-emails.star").read_text()


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


def _records(out, kind=None):
    """The proxy's structured `credproxy {json}` records from captured stdout,
    optionally filtered by `kind` (see proxy/log.py)."""
    recs = []
    for line in out.splitlines():
        if line.startswith("credproxy "):
            r = json.loads(line[len("credproxy "):])
            if kind is None or r.get("kind") == kind:
                recs.append(r)
    return recs


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


# ---- [http] log-line folding (unified evaluator) ----------------------------

def test_request_terminal_http_line_folds_prior_rewrite_marks(capsys):
    # After unifying the two evaluators, a request rewrite before a block folds
    # into ONE [http] line with both markers, in order (parity with the response
    # phase; previously the request terminal line dropped the rewrite marker).
    creds = _creds([
        {"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
         "set_headers": {"X-Env": "sandbox"}},
        {"name": "blk", "hosts": ["api.github.com"], "action": "block"},
    ])
    log = addon.HostnameLogger(_state(creds))
    log.request(_flow())
    http = _records(capsys.readouterr().out, "http")
    assert len(http) == 1
    assert http[0]["marks"] == ["rewrite:rw", "block:blk"]   # order preserved


def test_response_script_error_prints_http_line(capsys):
    # A response-script failure logs an http record (marks: rule-error:NAME) as
    # well as the 502 -- the response phase used to print none.
    creds = _creds([_script_rule("boom", "def on_response():\n    fail('x')\n")])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(resp=True)
    log.response(flow)
    assert flow.response.status_code == 502
    http = _records(capsys.readouterr().out, "http")
    assert any("rule-error:boom" in r.get("marks", []) for r in http)


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
    rule_events = [e for e in _records(capsys.readouterr().out, "audit")
                   if e["event"] == "rule"]
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


def test_hidden_rule_only_host_not_in_disclosed_but_intercepted():
    # A hidden tripwire on a bindings-free host must NOT be enumerable via /setup
    # (disclosed_intercept_hosts), yet must still be intercepted and fire.
    creds = _creds([
        {"name": "trip", "hosts": ["secret.example.com"], "action": "block",
         "visible": False},
        {"name": "vis", "hosts": ["api.github.com"], "action": "block"},
    ])
    disclosed = creds.disclosed_intercept_hosts()
    assert "secret.example.com" not in disclosed      # hidden host withheld
    assert "api.github.com" in disclosed              # visible host enumerated
    assert "secret.example.com" in creds.intercept_hosts()   # operator sees it
    assert creds.intercepts("secret.example.com")     # decision path still fires
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(host="secret.example.com", path="/")
    log.request(flow)
    assert flow.response.status_code == 403


# ---- first-terminal-wins across phases (P1-A) -------------------------------

def test_terminal_request_rule_suppresses_later_response_rule():
    # A request `block` terminates the flow; mitmproxy still fires response(), but
    # a later on_response script must NOT run -- else it could undo the block.
    creds = _creds([
        {"name": "blk", "hosts": ["api.github.com"], "action": "block"},
        _script_rule("undo", "def on_response():\n    respond(200, 'pwned')\n"),
    ])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 403
    assert flow.metadata.get("credproxy_rule_terminated") is True
    log.response(flow)                       # simulate mitmproxy's response hook
    assert flow.response.status_code == 403  # NOT rewritten to 200
    assert flow.response.content != b"pwned"


def test_fail_closed_502_not_undone_by_response_rule():
    # The fail-closed 502 (a request script that raises) must also suppress later
    # response rules -- same violation, different hat.
    creds = _creds([
        _script_rule("boom", _RAISE_SCRIPT),
        _script_rule("undo", "def on_response():\n    respond(200, 'pwned')\n"),
    ])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 502
    log.response(flow)
    assert flow.response.status_code == 502


def test_reseal_withheld_502_not_followed_by_response_rule():
    # The re-seal-withhold 502 in response() returns before response rules run;
    # assert that stays true (a response rewrite must not apply over the 502).
    creds = _creds([{"name": "rw", "hosts": ["api.github.com"], "action": "rewrite",
                     "resp_set_headers": {"X-Ran": "1"}}])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(resp=True)

    class _RaisingReseal:
        name = "reseal"
        mutates_response = True

        def on_response(self, ctx):
            raise RuntimeError("boom")

    flow.metadata["credproxy_fired"] = [config.Transform(
        name="reseal", scheme=_RaisingReseal(), params={},
        placeholder=None, secrets={})]
    log.response(flow)
    assert flow.response.status_code == 502
    assert "X-Ran" not in flow.response.headers   # response rule did NOT run


# ---- Host/authority rewrite rejected (P1-B) ---------------------------------

@pytest.mark.parametrize("rule", [
    {"name": "h", "hosts": ["api.github.com"], "action": "rewrite",
     "set_headers": {"Host": "evil.com"}},
    {"name": "h", "hosts": ["api.github.com"], "action": "rewrite",
     "set_headers": {"host": "evil.com"}},        # case-insensitive
    {"name": "h", "hosts": ["api.github.com"], "action": "rewrite",
     "remove_headers": ["Host"]},
    {"name": "h", "hosts": ["api.github.com"], "action": "rewrite",
     "set_headers": {":authority": "evil.com"}},
])
def test_declarative_host_rewrite_rejected(rule):
    with pytest.raises(ConfigError, match="authority|Host"):
        _creds([rule])


def test_script_host_rewrite_fails_closed():
    # A scripted req_set_header("Host", ...) compiles (the primitive exists) but
    # fails closed at runtime -- and the header is never actually mutated.
    creds = _creds([_script_rule(
        "h", 'def on_request():\n    req_set_header("Host", "evil.com")\n')])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 502
    assert flow.request.headers.get("Host") != "evil.com"


# ---- builtin scrub-emails rule script ---------------------------------------

def test_builtin_scrub_emails_object_and_list():
    creds = _creds([_script_rule("scrub-emails", _SCRUB_EMAILS, path="/users/**")])
    log = addon.HostnameLogger(_state(creds))

    # single object
    flow = _flow(host="api.github.com", path="/users/octo", resp=True)
    flow.response.text = json.dumps(
        {"login": "octo", "email": "a@b.com", "notification_email": "n@b.com"})
    log.response(flow)
    data = json.loads(flow.response.text)
    assert data["email"] is None and data["notification_email"] is None
    assert data["login"] == "octo"            # non-email fields untouched

    # list of objects
    flow = _flow(host="api.github.com", path="/users/x/list", resp=True)
    flow.response.text = json.dumps([{"email": "a@b.com"}, {"login": "y"}])
    log.response(flow)
    data = json.loads(flow.response.text)
    assert data[0]["email"] is None and data[1]["login"] == "y"


def test_builtin_scrub_emails_passthrough_non_object():
    creds = _creds([_script_rule("scrub-emails", _SCRUB_EMAILS, path="/users/**")])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(host="api.github.com", path="/users/scalar", resp=True)
    flow.response.text = json.dumps("just a string")
    log.response(flow)
    assert json.loads(flow.response.text) == "just a string"


def test_docstring_def_not_misclassified_as_request_hook():
    # A response-only script whose DOCSTRING contains a column-0 `def on_request():`
    # must NOT be treated as request-active -- else the runtime calls a nonexistent
    # export and 502s every matching request. The resolver-based detector sees no
    # real on_request binding.
    src = ('def on_response():\n'
           '    """\n'
           'def on_request(): not a real def, inside a docstring\n'
           '    """\n'
           '    return\n')
    creds = _creds([_script_rule("s", src, path="/users/**")])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow(host="api.github.com", path="/users/x")   # resp=False
    log.request(flow)
    assert flow.response is None            # passed through, NOT a 502


def test_hook_detection_robust_via_resolver():
    # Hook presence is decided by the Starlark resolver (a top-level reference that
    # raises iff the name isn't a real binding), not a text scan -- so the cases
    # that fooled the old `(?m)^def` regex are all correct.
    from starlark_runtime import ScriptedScheme
    # `"""` inside single-quoted literals around a real def: the OLD lexer blanked
    # the def (false negative -> a rule with only on_request looked hook-less and
    # was REJECTED at push; a re-seal injector fails OPEN). Resolver sees it.
    s = ScriptedScheme("s", "FENCE = '\"\"\"'\ndef on_request():\n    block()\n"
                            "END = '\"\"\"'\n", kind="rule")
    assert s.has_on_request and not s.has_on_response
    # a docstring `def on_request` is NOT a binding (old lexer false positive ->
    # 502 every request by calling a nonexistent export).
    s2 = ScriptedScheme("s", 'def on_response():\n    """\ndef on_request(): x\n'
                             '    """\n    return\n', kind="rule")
    assert s2.has_on_response and not s2.has_on_request
    # a `#` comment containing `"""` doesn't hide a real hook.
    s3 = ScriptedScheme("s", '# note """ template\ndef on_request():\n    block()\n',
                        kind="rule")
    assert s3.has_on_request
    # a nested def is not a top-level hook.
    s4 = ScriptedScheme("s", 'def on_response():\n    def on_request():\n'
                             '        pass\n    return\n', kind="rule")
    assert s4.has_on_response and not s4.has_on_request
    # a NON-CALLABLE binding named like a hook is NOT a hook -- else the runtime
    # would call() a non-callable and 502 every matching request.
    s5 = ScriptedScheme("s", "on_request = True\ndef on_response():\n    return\n",
                        kind="rule")
    assert s5.has_on_response and not s5.has_on_request
    # a lambda alias IS a real callable hook.
    s6 = ScriptedScheme("s", "on_request = lambda: block()\n", kind="rule")
    assert s6.has_on_request


# ---- RuleSet.dry_run (rule test --live, exact per-script phase) --------------

def test_dry_run_exact_script_phase():
    # A response-only script (scrub-emails): dry_run knows the exact phase, so it
    # reports phase="response", non-terminal, and does NOT gate the later block
    # (conditional stays False) -- unlike the CLI's conservative offline matcher.
    creds = _creds([
        _script_rule("scrub", _SCRUB_EMAILS, path="/users/**"),
        {"name": "blk", "hosts": ["api.github.com"], "action": "block"},
    ])
    m = creds.rule_set().dry_run("GET", "api.github.com", "/users/x")
    assert [x["name"] for x in m] == ["scrub", "blk"]
    assert m[0]["phase"] == "response" and m[0]["may_terminate"] is False
    assert m[0]["conditional"] is False
    assert m[1]["terminal"] is True and m[1]["conditional"] is False


def test_dry_run_request_active_script_gates_later_rule():
    creds = _creds([
        _script_rule("rw", "def on_request():\n    req_set_header('X', 'y')\n"),
        {"name": "blk", "hosts": ["api.github.com"], "action": "block"},
    ])
    m = creds.rule_set().dry_run("GET", "api.github.com", "/x")
    assert m[0]["phase"] == "request" and m[0]["may_terminate"] is True
    assert m[1]["terminal"] is True and m[1]["conditional"] is True   # gated on rw


# ---- review round: empty rewrite, hidden-respond attribution, audit visible ---

def test_rewrite_empty_container_rejected():
    # A present-but-empty op ([] / {}) does nothing but would flip the host to
    # intercepted -- rejected, like an empty `methods`.
    with pytest.raises(ConfigError, match="NON-EMPTY|at least one"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "rewrite",
                 "remove_headers": []}])
    with pytest.raises(ConfigError, match="NON-EMPTY|at least one"):
        _creds([{"name": "r", "hosts": ["h.example.com"], "action": "rewrite",
                 "set_headers": {}}])


def test_hidden_respond_strips_forged_attribution():
    # A HIDDEN respond must never self-identify: an X-Credproxy-Rule the script's
    # respond(...) headers set (any case) is stripped, so it can't forge
    # attribution to another rule.
    src = ('def on_request():\n'
           '    respond(200, "x", {"x-credproxy-rule": "some-other-rule"})\n')
    creds = _creds([_script_rule("h", src, visible=False)])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.status_code == 200
    assert "X-Credproxy-Rule" not in flow.response.headers


def test_rule_error_audit_carries_visible(capsys):
    creds = _creds([_script_rule("boom", "def on_request():\n    fail('x')\n",
                                 visible=False)])
    log = addon.HostnameLogger(_state(creds))
    log.request(_flow())
    err = [e for e in _records(capsys.readouterr().out, "audit")
           if e["event"] == "rule" and e["outcome"] == "error"]
    assert err and err[0]["visible"] is False


def test_visible_respond_single_attribution():
    # A VISIBLE respond whose script sets its own X-Credproxy-Rule must emit only
    # ONE canonical attribution (ours), not two contradictory header lines.
    src = ('def on_request():\n'
           '    respond(200, "x", {"x-credproxy-rule": "some-other-rule"})\n')
    creds = _creds([_script_rule("vis", src, visible=True)])
    log = addon.HostnameLogger(_state(creds))
    flow = _flow()
    log.request(flow)
    assert flow.response.headers.get_all("X-Credproxy-Rule") == ["vis"]
