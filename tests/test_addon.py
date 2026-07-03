"""Tests for proxy/addon.py — HostnameLogger intercept decision and scheme
injection (scheme-aware transforms)."""
import base64
from types import SimpleNamespace

from mitmproxy.test import tflow, tutils

import addon
import config
import schemes
from config import Transform


def _t(scheme, placeholder, real, *, header="Authorization", name="b"):
    """Build a Transform for `scheme` with a single `value` secret slot."""
    params = {} if scheme == "body" else {"header": header}
    return Transform(name, schemes.SCHEMES[scheme], params, placeholder,
                     {"value": real})


class FakeCreds:
    """Hand-rolled Credentials for unit tests."""

    def __init__(self, hosts: dict[str, list[Transform]]):
        self._hosts = hosts

    def intercepts(self, sni) -> bool:
        return bool(sni) and sni in self._hosts

    def intercept_hosts(self) -> set[str]:
        return set(self._hosts)

    def transforms_for(self, host: str) -> list[Transform]:
        return list(self._hosts.get(host, []))

    def inward_bindings(self) -> list:
        return []

    def rule_set(self):
        import rules
        return rules.RuleSet()


def make_state(hosts):
    """HostnameLogger reads `state.creds` fresh on each call; tests mimic that
    by wrapping FakeCreds in a SimpleNamespace with a `.creds` attribute."""
    return SimpleNamespace(creds=FakeCreds(hosts))


def make_clienthello(sni):
    return SimpleNamespace(
        client_hello=SimpleNamespace(sni=sni),
        ignore_connection=False,
    )


def make_flow(host="api.github.com", path="/user", headers=None):
    req = tutils.treq(host=host, path=path.encode())
    req.headers.clear()
    for k, v in (headers or {}).items():
        req.headers[k] = v
    return tflow.tflow(req=req)


# ---- tls_clienthello: intercept decision ----

def test_clienthello_intercepted_does_not_set_ignore():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello("api.github.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is False


def test_clienthello_passthrough_sets_ignore():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello("example.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is True


def test_clienthello_no_sni_passthrough():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello(None)
    log.tls_clienthello(data)
    assert data.ignore_connection is True


def test_clienthello_fails_safe_on_intercept_error():
    """A broken intercept decision (e.g. a pathological glob) must passthrough,
    not raise and take ALL TLS flows down."""
    class _Boom:
        def intercepts(self, sni):
            raise RuntimeError("bad pattern")

    log = addon.HostnameLogger(SimpleNamespace(creds=_Boom()))
    data = make_clienthello("api.example.com")
    log.tls_clienthello(data)                  # must not raise
    assert data.ignore_connection is True      # failed safe to passthrough


# ---- request: bearer substitution ----

def test_request_substitutes_placeholder():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL")]
    }))
    flow = make_flow(headers={"Authorization": "Bearer PH"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer REAL"


def test_request_no_substitution_when_placeholder_absent_in_value():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL")]
    }))
    flow = make_flow(headers={"Authorization": "Bearer not_the_placeholder"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer not_the_placeholder"


def test_request_no_substitution_when_header_absent():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL")]
    }))
    flow = make_flow(headers={})
    log.request(flow)
    assert "Authorization" not in flow.request.headers


def test_request_multiple_headers_substituted():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [
            _t("bearer", "PH1", "REAL1", header="Authorization", name="b1"),
            _t("bearer", "PH2", "REAL2", header="X-API-Key", name="b2"),
        ]
    }))
    flow = make_flow(headers={"Authorization": "PH1", "X-API-Key": "PH2"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "REAL1"
    assert flow.request.headers["X-API-Key"] == "REAL2"


def test_request_placeholder_appears_twice_in_one_value():
    """str.replace replaces all occurrences."""
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL", header="X-Weird")]
    }))
    flow = make_flow(headers={"X-Weird": "PH and PH again"})
    log.request(flow)
    assert flow.request.headers["X-Weird"] == "REAL and REAL again"


def test_request_non_intercepted_host_no_change():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL")]
    }))
    flow = make_flow(host="example.com", headers={"Authorization": "Bearer PH"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer PH"


# ---- glob host patterns through the addon (real BindingCredentials) ----

def _pattern_state(pattern):
    """A real config.BindingCredentials with one bearer binding scoped to a
    glob pattern -- exercises the addon's intercepts()/transforms_for() path."""
    creds = config.load_resolved({"bindings": [{
        "name": "b", "hosts": [pattern], "scheme": "bearer",
        "params": {"header": "Authorization"}, "secret": {"value": "REAL"},
        "placeholder": "PH",
    }]})
    return SimpleNamespace(creds=creds)


def test_clienthello_pattern_sni_intercepted():
    log = addon.HostnameLogger(_pattern_state("*.amazonaws.com"))
    data = make_clienthello("s3.us-east-1.amazonaws.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is False


def test_clienthello_pattern_non_match_passthrough():
    log = addon.HostnameLogger(_pattern_state("*.amazonaws.com"))
    data = make_clienthello("api.github.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is True


def test_request_substitutes_on_pattern_matched_host():
    log = addon.HostnameLogger(_pattern_state("*.amazonaws.com"))
    flow = make_flow(host="s3.eu-west-1.amazonaws.com",
                     headers={"Authorization": "Bearer PH"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer REAL"


def test_state_creds_swap_takes_effect_on_next_call():
    """In-process reload: mutating state.creds is visible to the next request."""
    state = make_state({"api.github.com": [_t("bearer", "OLD", "OLDREAL")]})
    log = addon.HostnameLogger(state)
    flow = make_flow(headers={"Authorization": "OLD"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "OLDREAL"

    state.creds = FakeCreds({"api.github.com": [_t("bearer", "NEW", "NEWREAL")]})
    flow2 = make_flow(headers={"Authorization": "NEW"})
    log.request(flow2)
    assert flow2.request.headers["Authorization"] == "NEWREAL"


# ---- request: basic decode-and-swap ----

def _basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def test_basic_swaps_password_component():
    log = addon.HostnameLogger(make_state({
        "github.com": [_t("basic", "PH", "REAL")]
    }))
    flow = make_flow(host="github.com", headers={"Authorization": _basic("alice", "PH")})
    log.request(flow)
    assert flow.request.headers["Authorization"] == _basic("alice", "REAL")


def test_basic_swaps_username_component():
    """A token in the username position (dummy password) is also swapped."""
    log = addon.HostnameLogger(make_state({
        "github.com": [_t("basic", "PH", "REAL")]
    }))
    flow = make_flow(host="github.com", headers={"Authorization": _basic("PH", "x-oauth-basic")})
    log.request(flow)
    assert flow.request.headers["Authorization"] == _basic("REAL", "x-oauth-basic")


def test_basic_swaps_with_lowercase_scheme_token():
    """The auth-scheme token is case-insensitive (RFC 7235): 'basic' works."""
    log = addon.HostnameLogger(make_state({
        "github.com": [_t("basic", "PH", "REAL")]
    }))
    blob = base64.b64encode(b"alice:PH").decode()
    flow = make_flow(host="github.com", headers={"Authorization": "basic " + blob})
    log.request(flow)
    assert flow.request.headers["Authorization"] == _basic("alice", "REAL")


def test_basic_no_swap_when_no_match():
    log = addon.HostnameLogger(make_state({
        "github.com": [_t("basic", "PH", "REAL")]
    }))
    orig = _basic("alice", "other")
    flow = make_flow(host="github.com", headers={"Authorization": orig})
    log.request(flow)
    assert flow.request.headers["Authorization"] == orig


# ---- request: body substitution ----

def test_body_substitutes_placeholder():
    log = addon.HostnameLogger(make_state({
        "login.example.com": [_t("body", "PH", "REAL")]
    }))
    flow = make_flow(host="login.example.com")
    flow.request.text = "grant_type=client_credentials&client_secret=PH"
    log.request(flow)
    assert flow.request.text == "grant_type=client_credentials&client_secret=REAL"


# ---- response: no-op seam + ResponseCtx ----

def test_response_hook_is_noop_for_substitute_schemes():
    """The response hook is plumbed but leaves request and response untouched
    for substitute schemes."""
    log = addon.HostnameLogger(make_state({
        "api.github.com": [_t("bearer", "PH", "REAL")]
    }))
    req = tutils.treq(host="api.github.com")
    req.headers.clear()
    req.headers["Authorization"] = "Bearer PH"
    flow = tflow.tflow(req=req, resp=True)
    flow.response.headers["X-Orig"] = "v"
    log.response(flow)  # must not raise
    assert flow.request.headers["Authorization"] == "Bearer PH"
    assert flow.response.headers["X-Orig"] == "v"


def test_response_ctx_reads_request_and_mutates_response():
    """ResponseCtx exposes the request that was answered (read-only) and the
    response headers/body (read/write) -- the re-seal seam."""
    req = tutils.treq(host="api.github.com", method=b"POST", path=b"/token")
    flow = tflow.tflow(req=req, resp=True)
    flow.response.headers["X-Token"] = "abc"
    ctx = schemes.ResponseCtx(flow, {"value": "s"}, {"k": "v"}, "ph")

    assert ctx.request_host == "api.github.com"
    assert ctx.request_method == "POST"
    assert ctx.request_path == "/token"
    assert ctx.header_get("X-Token") == "abc"   # reads the RESPONSE headers
    assert ctx.secret() == "s"
    assert ctx.params == {"k": "v"} and ctx.placeholder == "ph"

    ctx.header_set("X-New", "1")
    assert flow.response.headers["X-New"] == "1"
