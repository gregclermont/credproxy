"""Re-seal: the response-phase mint + dynamic-placeholder
store.

A dynamic placeholder is just a static one registered at runtime with a TTL, so
the data-plane swap reuses the bearer substitute. These tests cover the TTL
store, the RuntimeMinter, the built-in oauth2-reseal scheme end-to-end (token
endpoint request swap -> response mint+rewrite -> API-host swap), and the
scripted mint_into_json primitive.
"""
import json
from types import SimpleNamespace

import pytest
from mitmproxy.test import tflow, tutils

import addon
import config
import placeholders
import schemes


# ---- TTL store ---------------------------------------------------------------

def test_runtime_transform_ttl_expiry():
    clock = [1000.0]
    creds = config.BindingCredentials({}, clock=lambda: clock[0])
    t = config.Transform(name="x", scheme=schemes.SCHEMES["bearer"],
                         params={}, placeholder="ph", secrets={"value": "v"})
    creds.register_runtime("api.example.com", t, ttl=60)
    assert creds.transforms_for("api.example.com") == [t]
    assert "api.example.com" in creds.intercept_hosts()

    clock[0] = 1061.0  # past the 60s TTL
    assert creds.transforms_for("api.example.com") == []
    assert "api.example.com" not in creds.intercept_hosts()


def test_runtime_transform_no_ttl_is_permanent():
    clock = [0.0]
    creds = config.BindingCredentials({}, clock=lambda: clock[0])
    t = config.Transform(name="x", scheme=schemes.SCHEMES["bearer"],
                         params={}, placeholder="ph", secrets={"value": "v"})
    creds.register_runtime("h", t)              # ttl=None
    clock[0] = 1e9
    assert creds.transforms_for("h") == [t]


# ---- RuntimeMinter -----------------------------------------------------------

def test_runtime_minter_registers_bearer_swap_on_each_host():
    creds = config.BindingCredentials({})
    minter = config.RuntimeMinter(creds, lambda: "credproxy_FIXED")
    ph = minter.mint("TOKEN", 3600, ["a.com", "b.com"], "Authorization")
    assert ph == "credproxy_FIXED"
    for h in ("a.com", "b.com"):
        [tr] = creds.transforms_for(h)
        assert tr.scheme.name == "bearer"
        assert tr.placeholder == "credproxy_FIXED"
        assert tr.secrets == {"value": "TOKEN"}


def test_runtime_minter_requires_api_hosts():
    minter = config.RuntimeMinter(config.BindingCredentials({}), placeholders.generate)
    with pytest.raises(ValueError, match="api_host"):
        minter.mint("T", 60, [])


def test_mint_into_json_non_json_body_leaves_nothing_registered():
    creds = config.BindingCredentials({})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    flow = tflow.tflow(resp=True)
    flow.response.text = "not json"
    ctx = schemes.ResponseCtx(flow, {}, {}, None, minter=minter)
    with pytest.raises(Exception):
        ctx.mint_into_json("access_token", "TOK", 60, ["api.example.com"])
    assert creds.transforms_for("api.example.com") == []   # parse failed before mint


def test_mint_without_minter_raises():
    flow = tflow.tflow(resp=True)
    ctx = schemes.ResponseCtx(flow, {}, {}, None)           # no minter
    with pytest.raises(RuntimeError, match="minter"):
        ctx.mint("v", 60, ["h"])


# ---- built-in oauth2-reseal, end to end --------------------------------------

def _reseal_creds():
    return config.load_resolved({"bindings": [{
        "name": "oauth", "hosts": ["oauth.example.com"],
        "scheme": "oauth2-reseal",
        "params": {"api_hosts": ["api.example.com"]},
        "secret": {"value": "CLIENT_SECRET"}, "placeholder": "cs_PH",
    }]})


def test_oauth2_reseal_intercepts_api_hosts():
    creds = _reseal_creds()
    assert "oauth.example.com" in creds.intercept_hosts()
    assert "api.example.com" in creds.intercept_hosts()     # extra_intercept_hosts


def test_oauth2_reseal_full_flow():
    creds = _reseal_creds()

    # (1) token-endpoint request: the client_secret placeholder is swapped in.
    [t] = creds.transforms_for("oauth.example.com")
    treqf = tutils.treq(host="oauth.example.com", method=b"POST", path=b"/token",
                        content=b"grant_type=client_credentials&client_secret=cs_PH")
    rctx = schemes.RequestCtx(treqf, t.secrets, t.params, t.placeholder)
    assert t.scheme.on_request(rctx) is True
    assert "client_secret=CLIENT_SECRET" in treqf.text
    assert "cs_PH" not in treqf.text

    # (2) token-endpoint response: mint a placeholder + rewrite the body.
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "MINTED-TOKEN", "expires_in": 3600})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    respctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(respctx) is True

    body = json.loads(flow.response.text)
    ph = body["access_token"]
    assert ph != "MINTED-TOKEN"             # the workspace gets a placeholder
    assert ph.startswith("credproxy_")

    # (3) API-host request: the workspace sends the placeholder; the runtime
    #     swap replaces it with the real minted token.
    [api_t] = creds.transforms_for("api.example.com")
    areq = tutils.treq(host="api.example.com", method=b"GET", path=b"/v1/thing")
    areq.headers["Authorization"] = "Bearer " + ph
    actx = schemes.RequestCtx(areq, api_t.secrets, api_t.params, api_t.placeholder)
    assert api_t.scheme.on_request(actx) is True
    assert areq.headers["Authorization"] == "Bearer MINTED-TOKEN"


def test_oauth2_reseal_skips_non_200():
    creds = _reseal_creds()
    [t] = creds.transforms_for("oauth.example.com")
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 401
    flow.response.text = json.dumps({"error": "invalid_client"})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    ctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(ctx) is False
    assert creds.transforms_for("api.example.com") == []
    assert json.loads(flow.response.text) == {"error": "invalid_client"}


def test_oauth2_reseal_ttl_from_expires_in():
    clock = [0.0]
    creds = config.load_resolved(
        {"bindings": [{
            "name": "oauth", "hosts": ["oauth.example.com"],
            "scheme": "oauth2-reseal", "params": {"api_hosts": ["api.example.com"]},
            "secret": {"value": "CS"}, "placeholder": "cs_PH",
        }]},
    )
    creds._clock = lambda: clock[0]   # control expiry
    [t] = creds.transforms_for("oauth.example.com")
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "TOK", "expires_in": 100})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    ctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(ctx) is True
    assert len(creds.transforms_for("api.example.com")) == 1
    clock[0] = 101.0
    assert creds.transforms_for("api.example.com") == []   # expired per expires_in


# ---- scripted re-seal via the mint_into_json primitive -----------------------

RESEAL_STAR = """
def on_request():
    text = req_body()
    ph = placeholder()
    if not text or ph == None or ph not in text:
        return False
    req_set_body(text.replace(ph, secret()))
    return True

def on_response():
    if resp_status() != 200:
        return False
    tok = resp_json()
    if tok == None:
        return False
    access = tok.get("access_token")
    if access == None:
        return False
    mint_into_json("access_token", access, tok.get("expires_in", 3600))
    return True
"""


def test_scripted_reseal_via_mint_primitive():
    from starlark_runtime import ScriptedScheme
    s = ScriptedScheme("reseal", RESEAL_STAR, family="substitute", slots=("value",),
                       location_kind="body", header_default=None)
    creds = config.BindingCredentials({})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "MINTED", "expires_in": 1200})
    ctx = schemes.ResponseCtx(flow, {"value": "CS"},
                              {"api_hosts": ["api.example.com"]}, "cs_PH", minter=minter)
    assert s.on_response(ctx) is True
    ph = json.loads(flow.response.text)["access_token"]
    assert ph != "MINTED" and ph.startswith("credproxy_")
    [tr] = creds.transforms_for("api.example.com")
    assert tr.secrets == {"value": "MINTED"}
    assert tr.placeholder == ph


# ---- multi-binding disambiguation (open question (a), now closed) ------------

def test_two_reseal_bindings_share_one_token_endpoint():
    """Two re-seal bindings on the SAME token endpoint with distinct placeholders
    are allowed (distinct placeholders disambiguate)."""
    creds = config.load_resolved({"bindings": [
        {"name": "A", "hosts": ["login.example.com"], "scheme": "oauth2-reseal",
         "params": {"api_hosts": ["api-a.com"]}, "secret": {"value": "SECRET_A"},
         "placeholder": "ph_a"},
        {"name": "B", "hosts": ["login.example.com"], "scheme": "oauth2-reseal",
         "params": {"api_hosts": ["api-b.com"]}, "secret": {"value": "SECRET_B"},
         "placeholder": "ph_b"},
    ]})
    assert len(creds.transforms_for("login.example.com")) == 2


def test_multi_reseal_disambiguation_routes_response_to_the_right_binding():
    """The response hook re-seals ONLY for the binding whose on_request fired on
    this flow (correlated via flow.metadata) -- so app A's token lands on A's API
    host, never B's, even though both bindings share the token endpoint."""
    creds = config.load_resolved({"bindings": [
        {"name": "A", "hosts": ["login.example.com"], "scheme": "oauth2-reseal",
         "params": {"api_hosts": ["api-a.com"]}, "secret": {"value": "SECRET_A"},
         "placeholder": "ph_a"},
        {"name": "B", "hosts": ["login.example.com"], "scheme": "oauth2-reseal",
         "params": {"api_hosts": ["api-b.com"]}, "secret": {"value": "SECRET_B"},
         "placeholder": "ph_b"},
    ]})
    log = addon.HostnameLogger(SimpleNamespace(creds=creds))

    # App A's token request carries only ph_a -> only binding A fires.
    req = tutils.treq(host="login.example.com", method=b"POST", path=b"/token",
                      content=b"grant_type=client_credentials&client_secret=ph_a")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    assert "client_secret=SECRET_A" in flow.request.text   # A injected its secret
    assert "ph_b" not in flow.request.text and "SECRET_B" not in flow.request.text
    assert [t.name for t in flow.metadata["credproxy_fired"]] == ["A"]

    # Token response -> only A re-seals.
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "TOKEN_A", "expires_in": 3600})
    log.response(flow)

    [a_swap] = creds.transforms_for("api-a.com")
    assert a_swap.secrets == {"value": "TOKEN_A"}      # A's token on A's API host
    assert creds.transforms_for("api-b.com") == []     # B untouched
    assert json.loads(flow.response.text)["access_token"] != "TOKEN_A"  # rewritten


def test_response_hook_skips_when_no_binding_fired():
    """If on_request fired for nothing on this flow, the response hook is inert
    (no minting, no body rewrite)."""
    creds = config.load_resolved({"bindings": [
        {"name": "A", "hosts": ["login.example.com"], "scheme": "oauth2-reseal",
         "params": {"api_hosts": ["api-a.com"]}, "secret": {"value": "SECRET_A"},
         "placeholder": "ph_a"},
    ]})
    log = addon.HostnameLogger(SimpleNamespace(creds=creds))
    # A request that does NOT carry the placeholder -> A.on_request returns False.
    req = tutils.treq(host="login.example.com", method=b"POST", path=b"/token",
                      content=b"grant_type=client_credentials")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    assert "credproxy_fired" not in flow.metadata
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "TOKEN_A", "expires_in": 3600})
    log.response(flow)
    assert creds.transforms_for("api-a.com") == []
    assert json.loads(flow.response.text)["access_token"] == "TOKEN_A"  # not rewritten


# ---- C1: re-seal must never leak the real minted token to the workspace ------

def test_oauth2_reseal_requires_api_hosts_at_config_load():
    """`api_hosts` is load-bearing: without it on_response can't mint, raises, and
    the original token response would otherwise reach the workspace. Reject the
    binding at config load (missing key OR present-but-empty list) rather than
    failing open at the first token response."""
    base = {"name": "oauth", "hosts": ["oauth.example.com"],
            "scheme": "oauth2-reseal", "secret": {"value": "CS"},
            "placeholder": "cs_PH"}
    with pytest.raises(config.ConfigError, match="api_hosts"):       # missing
        config.load_resolved({"bindings": [dict(base)]})
    with pytest.raises(config.ConfigError, match="api_hosts"):       # empty list
        config.load_resolved({"bindings": [dict(base, params={"api_hosts": []})]})


def test_oauth2_reseal_real_token_absent_from_workspace_body():
    """The happy path must scrub: the real minted token is gone from the body the
    workspace receives (a placeholder takes its place)."""
    creds = _reseal_creds()
    [t] = creds.transforms_for("oauth.example.com")
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "MINTED-TOKEN", "expires_in": 3600})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    ctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(ctx) is True
    assert "MINTED-TOKEN" not in flow.response.text


class _RaisingReseal:
    """A re-seal-family scheme whose on_response always raises AFTER on_request
    fired -- models a mint/rewrite failure on a token-endpoint response."""
    name = "boom"
    family = "substitute"
    slots = ("value",)
    location_kind = "body"
    header_default = None
    mutates_response = True

    def on_request(self, ctx) -> bool:
        return True

    def on_response(self, ctx) -> bool:
        raise RuntimeError("mint blew up")


class _OneTransform:
    """Minimal Credentials exposing a single transform on one host."""
    def __init__(self, host, transform):
        self._host, self._t = host, transform

    def intercepts(self, sni):
        return sni == self._host

    def intercept_hosts(self):
        return {self._host}

    def transforms_for(self, host):
        return [self._t] if host == self._host else []

    def inward_bindings(self):
        return []

    def rule_set(self):
        import rules
        return rules.RuleSet()

    def register_runtime(self, host, transform, ttl=None):
        pass


def test_response_fails_closed_when_reseal_scheme_raises():
    """If a response-mutating (re-seal) binding fired but its on_response raises,
    the addon must WITHHOLD the original token-endpoint body -- the workspace gets
    a 502, never the real minted token."""
    t = config.Transform("boom", _RaisingReseal(), {}, "PH", {"value": "CS"})
    log = addon.HostnameLogger(SimpleNamespace(creds=_OneTransform("login.example.com", t)))
    req = tutils.treq(host="login.example.com", method=b"POST", path=b"/token",
                      content=b"x")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    assert [x.name for x in flow.metadata["credproxy_fired"]] == ["boom"]
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "REAL-MINTED-TOKEN"})
    log.response(flow)
    assert flow.response.status_code == 502
    assert b"REAL-MINTED-TOKEN" not in flow.response.content


def test_response_does_not_fail_closed_for_substitute_scheme_error():
    """A substitute/sign scheme doesn't mutate the response, so an on_response
    error there leaks nothing -- the addon forwards the response untouched."""
    class _RaisingBearer(_RaisingReseal):
        name = "bsub"
        mutates_response = False

    t = config.Transform("bsub", _RaisingBearer(), {}, "PH", {"value": "CS"})
    log = addon.HostnameLogger(SimpleNamespace(creds=_OneTransform("api.example.com", t)))
    req = tutils.treq(host="api.example.com", method=b"GET", path=b"/x")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    flow.response.status_code = 200
    flow.response.text = "ok"
    log.response(flow)
    assert flow.response.status_code == 200      # forwarded, not withheld
    assert flow.response.text == "ok"


def test_response_reseals_against_request_time_binding_after_config_swap():
    """A POST /admin/config landing between the token request and its response
    must NOT let the real token through: the response hook re-seals against the
    request-time binding, not a fresh lookup in the swapped-in config."""
    state = SimpleNamespace(creds=_reseal_creds())
    log = addon.HostnameLogger(state)
    req = tutils.treq(host="oauth.example.com", method=b"POST", path=b"/token",
                      content=b"grant_type=client_credentials&client_secret=cs_PH")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    assert flow.metadata.get("credproxy_fired")          # binding A fired
    # Config swapped out from under the in-flight token request.
    state.creds = config.load_resolved({"bindings": []})
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "MINTED-TOKEN", "expires_in": 3600})
    log.response(flow)
    assert "MINTED-TOKEN" not in flow.response.text       # still scrubbed
    assert json.loads(flow.response.text)["access_token"].startswith("credproxy_")


# scripted re-seal: on_response that errors (no api_hosts -> mint raises) used to
# swallow the error and forward the token; it now fails closed through the addon.
_SCRIPTED_RESEAL_NO_API_HOSTS = (
    "def on_request():\n"
    "    t = req_body()\n"
    "    ph = placeholder()\n"
    "    if not t or ph == None or ph not in t:\n"
    "        return False\n"
    "    req_set_body(t.replace(ph, secret()))\n"
    "    return True\n"
    "def on_response():\n"
    "    tok = resp_json()\n"
    "    mint_into_json('access_token', tok['access_token'], 3600)\n"  # no api_hosts -> raises
    "    return True\n"
)


def test_scripted_reseal_fails_closed_when_on_response_raises():
    from starlark_runtime import ScriptedScheme
    scheme = ScriptedScheme("reseal", _SCRIPTED_RESEAL_NO_API_HOSTS, family="substitute",
                            slots=("value",), location_kind="body", header_default=None)
    t = config.Transform("r", scheme, {}, "cs_PH", {"value": "CS"})   # params: no api_hosts
    log = addon.HostnameLogger(SimpleNamespace(creds=_OneTransform("oauth.example.com", t)))
    req = tutils.treq(host="oauth.example.com", method=b"POST", path=b"/token",
                      content=b"grant_type=client_credentials&client_secret=cs_PH")
    flow = tflow.tflow(req=req, resp=True)
    log.request(flow)
    assert flow.metadata.get("credproxy_fired")
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "REAL-MINTED-TOKEN", "expires_in": 3600})
    log.response(flow)
    assert flow.response.status_code == 502
    assert b"REAL-MINTED-TOKEN" not in flow.response.content


# ---- V4 M4: the live runtime layer survives a config re-push -----------------

def _bearer_transform(name, ph, real):
    return config.Transform(name, schemes.SCHEMES["bearer"],
                            {"header": "Authorization"}, ph, {"value": real})


def test_adopt_runtime_carries_live_entries():
    clock = [0.0]
    old = config.BindingCredentials({}, clock=lambda: clock[0])
    old.register_runtime("api.example.com", _bearer_transform("r", "PH", "TOK"), ttl=100)
    new = config.BindingCredentials({}, clock=lambda: clock[0])
    new.adopt_runtime(old)
    assert [t.name for t in new.transforms_for("api.example.com")] == ["r"]
    assert new.intercepts("api.example.com")          # the API host stays intercepted


def test_adopt_runtime_drops_expired_entries():
    clock = [0.0]
    old = config.BindingCredentials({}, clock=lambda: clock[0])
    old.register_runtime("api.example.com", _bearer_transform("r", "PH", "TOK"), ttl=10)
    clock[0] = 20.0                                   # past the TTL
    new = config.BindingCredentials({}, clock=lambda: clock[0])
    new.adopt_runtime(old)
    assert new.transforms_for("api.example.com") == []


def test_minted_token_survives_config_repush():
    """A routine /admin/config re-push (apply/start) rebuilds creds; the live
    re-seal placeholder for an already-minted token must carry over, or the
    in-flight token becomes unresolvable until the next mint."""
    creds = _reseal_creds()
    [t] = creds.transforms_for("oauth.example.com")
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = json.dumps({"access_token": "MINTED", "expires_in": 3600})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    ctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(ctx) is True
    [swap] = creds.transforms_for("api.example.com")
    assert swap.secrets == {"value": "MINTED"}

    # Re-push: fresh creds (no runtime) + adopt the live layer (what admin does).
    new = _reseal_creds()
    assert new.transforms_for("api.example.com") == []
    new.adopt_runtime(creds)
    [survived] = new.transforms_for("api.example.com")
    assert survived.secrets == {"value": "MINTED"}    # minted token preserved


# ---- TTL sanity: no permanent / negative runtime entries ---------------------

def test_mint_rejects_non_finite_or_negative_ttl():
    creds = config.BindingCredentials({})
    minter = config.RuntimeMinter(creds, placeholders.generate)
    for bad in (float("inf"), float("nan"), -5):
        with pytest.raises(ValueError, match="finite"):
            minter.mint("v", bad, ["api.example.com"])


def test_oauth2_reseal_infinite_expires_in_uses_fallback_ttl():
    """A token response with non-finite expires_in (JSON `Infinity`) must NOT mint
    a permanent runtime entry -- the configured fallback TTL applies, so it
    expires."""
    clock = [0.0]
    creds = config.load_resolved({"bindings": [{
        "name": "oauth", "hosts": ["oauth.example.com"], "scheme": "oauth2-reseal",
        "params": {"api_hosts": ["api.example.com"], "ttl": "100"},
        "secret": {"value": "CS"}, "placeholder": "cs_PH"}]})
    creds._clock = lambda: clock[0]
    [t] = creds.transforms_for("oauth.example.com")
    flow = tflow.tflow(resp=True)
    flow.response.status_code = 200
    flow.response.text = '{"access_token": "TOK", "expires_in": Infinity}'
    minter = config.RuntimeMinter(creds, placeholders.generate)
    ctx = schemes.ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
    assert t.scheme.on_response(ctx) is True
    assert len(creds.transforms_for("api.example.com")) == 1     # minted
    clock[0] = 101.0
    assert creds.transforms_for("api.example.com") == []         # expired (not permanent)


# ---- audit attribution: the minted transform names its SOURCE binding --------

def test_runtime_minter_names_transform_with_source_binding():
    creds = config.BindingCredentials({})
    minter = config.RuntimeMinter(creds, lambda: "credproxy_PH",
                                  source_binding="gh-token")
    minter.mint("TOKEN", 3600, ["api.example.com"])
    [tr] = creds.transforms_for("api.example.com")
    assert tr.name == "reseal:gh-token"          # NOT the placeholder prefix


def test_reseal_audit_correlates_source_binding(capsys):
    # Drive the token round-trip AND an API-host request through the addon, then
    # assert the later injection of the minted placeholder audits `reseal:oauth`
    # -- correlatable with the `reseal` mint event's `oauth` binding.
    creds = _reseal_creds()
    log = addon.HostnameLogger(SimpleNamespace(creds=creds))

    tf = tflow.tflow(
        req=tutils.treq(host="oauth.example.com", method=b"POST", path=b"/token",
                        content=b"grant_type=client_credentials&client_secret=cs_PH"),
        resp=True)
    tf.response.status_code = 200
    tf.response.text = json.dumps({"access_token": "MINTED", "expires_in": 3600})
    log.request(tf)                       # token-endpoint request: injects + fires
    log.response(tf)                      # mints the placeholder (source=oauth)
    ph = json.loads(tf.response.text)["access_token"]

    af = tflow.tflow(req=tutils.treq(host="api.example.com", method=b"GET",
                                     path=b"/v1/x"))
    af.request.headers["Authorization"] = "Bearer " + ph
    log.request(af)                       # API-host request: runtime swap fires

    events = [json.loads(l[len("credproxy "):]) for l in
              capsys.readouterr().out.splitlines() if l.startswith("credproxy ")]
    events = [e for e in events if e.get("kind") == "audit"]
    assert any(e["event"] == "reseal" and e["binding"] == "oauth"
               and e["scheme"] == "oauth2-reseal" for e in events)
    assert any(e["event"] == "inject" and e["binding"] == "reseal:oauth"
               for e in events)          # correlatable, not a synthetic ph id
