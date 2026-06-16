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
    assert flow.metadata["credproxy_fired"] == ["A"]

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
