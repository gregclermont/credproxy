"""Tests for the sandboxed Starlark runtime (proxy/starlark_runtime.py).

The dogfood `.star` re-implementations of bearer/basic/body must behave
IDENTICALLY to the Python built-ins (that's the point of dogfooding), the
sandbox must reject `load()`, errors must fail closed, and a runaway must time
out. A Python-vs-Starlark micro-benchmark reports the per-call cost.

API shape ("option B"): hooks are zero-arg (`def on_request():`) and
primitives read an IMPLICIT ctx the runtime binds for the call -- a script never
threads or holds a ctx. Stateful primitives are flat, prefixed `req_`/`resp_`
which also encodes the phase.
"""
import base64
import time
from pathlib import Path

import pytest
import starlark
from mitmproxy.test import tflow, tutils

import schemes
from starlark_runtime import ScriptedScheme

SCRIPTS = (Path(__file__).resolve().parents[1]
           / "cli" / "credproxy_cli" / "builtin" / "scripts")


def _ctx(*, headers=None, body=None, secrets=None, params=None, ph="PH"):
    req = tutils.treq(host="api.github.com", method=b"GET", path=b"/",
                      content=(body.encode() if body is not None else b""))
    req.headers.clear()
    for k, v in (headers or {}).items():
        req.headers[k] = v
    ctx = schemes.RequestCtx(req, secrets or {"value": "REAL"}, params or {}, ph)
    return ctx, req


def _resp_ctx(*, status=200, body="", secrets=None, params=None, ph=None):
    """A response-phase ctx over a tflow (request + response present)."""
    flow = tflow.tflow(resp=True)
    flow.response.status_code = status
    flow.response.text = body
    ctx = schemes.ResponseCtx(flow, secrets or {}, params or {}, ph)
    return ctx, flow


def _scripted(name):
    return ScriptedScheme(name, (SCRIPTS / f"{name}.star").read_text())


def _basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


# ---- the dogfood scripts run at all ------------------------------------------

def test_scripted_bearer_swaps():
    s = _scripted("bearer")
    ctx, req = _ctx(headers={"Authorization": "Bearer PH"},
                    params={"header": "Authorization"})
    assert s.on_request(ctx) is True
    assert req.headers["Authorization"] == "Bearer REAL"


def test_scripted_basic_swaps_password():
    s = _scripted("basic")
    ctx, req = _ctx(headers={"Authorization": _basic("alice", "PH")})
    assert s.on_request(ctx) is True
    assert req.headers["Authorization"] == _basic("alice", "REAL")


def test_scripted_body_swaps():
    s = _scripted("body")
    ctx, req = _ctx(body="client_secret=PH&x=1")
    assert s.on_request(ctx) is True
    assert req.text == "client_secret=REAL&x=1"


# ---- behavioural equivalence with the Python built-ins -----------------------

@pytest.mark.parametrize("header_val", [
    "Bearer PH", "token PH", "Bearer not_the_placeholder", None,
])
def test_bearer_equivalence(header_val):
    py = schemes.SCHEMES["bearer"]
    st = _scripted("bearer")
    headers = {"Authorization": header_val} if header_val is not None else {}
    cpy, rpy = _ctx(headers=dict(headers), params={"header": "Authorization"})
    cst, rst = _ctx(headers=dict(headers), params={"header": "Authorization"})
    assert py.on_request(cpy) == st.on_request(cst)
    assert rpy.headers.get("Authorization") == rst.headers.get("Authorization")


@pytest.mark.parametrize("auth", [
    _basic("alice", "PH"),            # placeholder in password
    _basic("PH", "x-oauth-basic"),    # placeholder in username
    _basic("alice", "other"),         # no match
    "basic " + base64.b64encode(b"alice:PH").decode(),  # lowercase scheme token
    "Bearer PH",                      # not Basic at all
    "Basic !!not-base64!!",           # undecodable blob (fail closed)
    None,                             # header absent
])
def test_basic_equivalence(auth):
    py = schemes.SCHEMES["basic"]
    st = _scripted("basic")
    headers = {"Authorization": auth} if auth is not None else {}
    cpy, rpy = _ctx(headers=dict(headers))
    cst, rst = _ctx(headers=dict(headers))
    assert py.on_request(cpy) == st.on_request(cst)
    assert rpy.headers.get("Authorization") == rst.headers.get("Authorization")


@pytest.mark.parametrize("body", [
    "client_secret=PH&x=1", "no placeholder here", "",
])
def test_body_equivalence(body):
    py = schemes.SCHEMES["body"]
    st = _scripted("body")
    cpy, rpy = _ctx(body=body)
    cst, rst = _ctx(body=body)
    assert py.on_request(cpy) == st.on_request(cst)
    assert rpy.text == rst.text


# ---- sign-family crypto/encoding primitives ----------------------------------

def test_primitive_hashes():
    from starlark_runtime import _sha1_hex, _sha256_hex, _hmac_sha256_hex
    import hashlib
    import hmac as _hmac
    assert _sha1_hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert _sha256_hex("abc") == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert _hmac_sha256_hex("k", "m") == \
        _hmac.new(b"k", b"m", hashlib.sha256).hexdigest()


def test_primitive_carrier_hmac_matches_hex():
    """The carrier HMAC (base64 key in, base64 MAC out) transcoded to hex equals
    the convenience hex form for a single round."""
    from starlark_runtime import _hmac_sha256, _hmac_sha256_hex, _b64_to_hex
    key, msg = "secret", "message"
    chained = _b64_to_hex(_hmac_sha256(base64.b64encode(key.encode()).decode(), msg))
    assert chained == _hmac_sha256_hex(key, msg)


def test_carrier_hmac_chains_like_sigv4():
    """The headline gap the carrier form closes: AWS SigV4's 4-round key
    derivation over RAW bytes, ending in a hex signature. Cross-checked against
    a straight stdlib reference so the test doesn't hardcode a vector."""
    from starlark_runtime import _hmac_sha256, _b64_to_hex
    import hashlib
    import hmac as _hmac

    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    parts = ("20150830", "us-east-1", "iam", "aws4_request")
    sts = ("AWS4-HMAC-SHA256\n20150830T123600Z\n"
           "20150830/us-east-1/iam/aws4_request\n" + "0" * 64)

    # reference: chain raw bytes with stdlib
    rk = ("AWS4" + secret).encode()
    for p in parts:
        rk = _hmac.new(rk, p.encode(), hashlib.sha256).digest()
    expected = _hmac.new(rk, sts.encode(), hashlib.sha256).hexdigest()

    # our carrier primitives: base64 carrier chained, transcoded to hex
    k = base64.b64encode(("AWS4" + secret).encode()).decode()
    for p in parts:
        k = _hmac_sha256(k, p)
    assert _b64_to_hex(_hmac_sha256(k, sts)) == expected
    assert len(expected) == 64


def test_primitive_b64url_roundtrip():
    from starlark_runtime import _b64url_encode, _b64url_decode
    enc = _b64url_encode("subject?>")          # exercises url-safe + padding
    assert "=" not in enc and "+" not in enc and "/" not in enc
    for s in ("", "a", "subject?>", "hello world", "πλ"):
        assert _b64url_decode(_b64url_encode(s)) == s


def test_primitive_carrier_transcode_roundtrip():
    from starlark_runtime import _b64_to_hex, _hex_to_b64
    blob = base64.b64encode(b"\x00\x01\x02\xfevalue").decode()
    assert _hex_to_b64(_b64_to_hex(blob)) == blob


def test_primitive_json_roundtrip():
    from starlark_runtime import _json_encode, _json_decode
    assert _json_encode({"alg": "RS256", "typ": "JWT"}) == '{"alg":"RS256","typ":"JWT"}'
    assert _json_decode('{"a":1,"b":[2,3]}') == {"a": 1, "b": [2, 3]}


def test_primitive_now_is_unix_int():
    from starlark_runtime import _now, _now_ms
    assert isinstance(_now(), int) and abs(_now() - int(time.time())) < 5
    assert _now_ms() >= _now() * 1000


def test_primitive_rs256_sign_verifies():
    from starlark_runtime import _rs256_sign
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    msg = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0"
    sig_b64 = _rs256_sign(pem, msg)
    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    # No exception == valid RS256 signature.
    key.public_key().verify(sig, msg.encode(), padding.PKCS1v15(), hashes.SHA256())


def test_primitive_jwt_encode_sign_and_decode():
    """jwt_encode_sign owns segment assembly + signing; jwt_decode_or_none reads
    claims back (no signature verification) or returns None for a non-JWT."""
    from starlark_runtime import _jwt_encode_sign, _jwt_decode_or_none
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    tok = _jwt_encode_sign({"alg": "RS256", "typ": "JWT"}, {"iss": "x", "exp": 123}, pem)
    parts = tok.split(".")
    assert len(parts) == 3
    sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    key.public_key().verify(sig, (parts[0] + "." + parts[1]).encode(),
                            padding.PKCS1v15(), hashes.SHA256())
    assert _jwt_decode_or_none(tok) == {"iss": "x", "exp": 123}
    assert _jwt_decode_or_none("not-a-jwt") is None


# ---- response phase (re-seal seam) -------------------------------------------

def test_response_phase_reads_and_mutates():
    """on_response can read the status + parse the body (resp_json) and mutate
    the response."""
    src = ("def on_response():\n"
           "    if resp_status() != 200:\n"
           "        return False\n"
           "    tok = resp_json()\n"
           "    if tok == None:\n"
           "        return False\n"
           "    resp_set_header('X-Token', tok['access_token'])\n"
           "    return True\n")
    s = ScriptedScheme("reseal", src)
    rc, flow = _resp_ctx(body='{"access_token":"ABC"}')
    assert s.on_response(rc) is True
    assert flow.response.headers["X-Token"] == "ABC"


def test_resp_json_is_total_on_non_json():
    src = ("def on_response():\n"
           "    if resp_json() == None:\n"
           "        resp_set_header('X', 'none')\n"
           "        return True\n"
           "    return False\n")
    s = ScriptedScheme("rj", src)
    rc, flow = _resp_ctx(body="not json at all")
    assert s.on_response(rc) is True
    assert flow.response.headers["X"] == "none"


def test_req_host_returns_hostname_in_transparent_mode():
    """Regression for #7: req_host() reads pretty_host, so it returns the
    hostname even when the connection target (flow.request.host) is an IP."""
    req = tutils.treq(host="10.0.0.5", method=b"GET", path=b"/", content=b"")
    req.headers.clear()
    req.headers["Host"] = "api.example.com"
    ctx = schemes.RequestCtx(req, {"value": "x"}, {}, "PH")
    s = ScriptedScheme(
        "h", "def on_request():\n    req_set_header('X-Seen-Host', req_host())\n    return True\n")
    assert s.on_request(ctx) is True
    assert req.headers["X-Seen-Host"] == "api.example.com"   # not 10.0.0.5


def test_req_metadata_getters_readable_in_response_phase():
    """Request METADATA getters (req_host/method/path -- no secret) read the
    ANSWERED request during on_response. Content getters are gated (see below)."""
    src = ("def on_response():\n"
           "    resp_set_header('X-Host', req_host())\n"
           "    return True\n")
    s = ScriptedScheme("rh", src)
    rc, flow = _resp_ctx()
    assert s.on_response(rc) is True
    assert flow.response.headers["X-Host"] == flow.request.host


def test_secret_is_request_phase_only():
    """secret() is unreachable in on_response: the durable secret must never be
    movable into the response the workspace receives. The hook fails closed."""
    from starlark_runtime import ScriptResponseError
    s = ScriptedScheme(
        "leak", "def on_response():\n    resp_set_body(secret())\n    return True\n")
    rc, flow = _resp_ctx(secrets={"value": "SUPER-SECRET-XYZZY"}, body="orig")
    with pytest.raises(ScriptResponseError):
        s.on_response(rc)
    assert flow.response.text == "orig"          # response left untouched
    assert "SUPER-SECRET-XYZZY" not in flow.response.text


def test_request_content_reads_are_request_phase_only():
    """req_body()/req_header() are gated out of on_response: there they would read
    the request the secret was injected into, a back-door to the same leak."""
    from starlark_runtime import ScriptResponseError
    for prim in ("req_body()", "req_header('Authorization')", "req_body_b64()"):
        s = ScriptedScheme(
            "g", f"def on_response():\n    resp_set_body({prim})\n    return True\n")
        rc, _ = _resp_ctx(body="orig")
        with pytest.raises(ScriptResponseError):
            s.on_response(rc)


def test_resp_primitive_in_request_phase_fails_closed():
    """A `resp_*` primitive in on_request hits the phase guard -> fail closed."""
    s = ScriptedScheme("g", "def on_request():\n    return resp_status()\n")
    ctx, req = _ctx(headers={"Authorization": "Bearer PH"})
    assert s.on_request(ctx) is False
    assert req.headers["Authorization"] == "Bearer PH"  # untouched


def test_req_mutation_in_response_phase_fails_closed():
    """A request-mutating primitive in on_response hits the phase guard. The
    response hook now RAISES (so the addon withholds the response) rather than
    silently returning False and forwarding a possibly token-bearing body."""
    from starlark_runtime import ScriptResponseError
    s = ScriptedScheme("g", "def on_response():\n    req_set_header('X', 'Y')\n    return True\n")
    rc, flow = _resp_ctx()
    with pytest.raises(ScriptResponseError):
        s.on_response(rc)
    assert "X" not in flow.response.headers


# ---- sandbox + fail-closed + timeout -----------------------------------------

def test_sandbox_rejects_load_at_compile():
    """A script that uses load() can't pull in other files -- it fails to
    compile (no FileLoader is provided)."""
    with pytest.raises(starlark.StarlarkError):
        ScriptedScheme("evil", 'load("other.star", "f")\ndef on_request():\n    return True\n')


def test_sandbox_has_no_print():
    """print is not in Globals.standard(), so a script can't write to stdout
    (an unknown global is rejected at eval/load time)."""
    with pytest.raises(starlark.StarlarkError):
        ScriptedScheme("p", 'def on_request():\n    print("x")\n    return True\n')


def test_script_runtime_error_fails_closed():
    """A script that errors at run time returns False (request unmodified),
    never raising into the addon."""
    s = ScriptedScheme("boom", 'def on_request():\n    fail("kaboom")\n')
    ctx, req = _ctx(headers={"Authorization": "Bearer PH"})
    assert s.on_request(ctx) is False
    assert req.headers["Authorization"] == "Bearer PH"  # untouched


def test_script_error_does_not_leak_secret_to_stdout(capsys):
    """A script that does fail(secret()) must NOT leak the credential to proxy
    stdout -- the runtime logs the exception type only, never its message."""
    s = ScriptedScheme("leak", 'def on_request():\n    fail(secret())\n')
    ctx, _ = _ctx(secrets={"value": "SUPER-SECRET-XYZZY"})
    assert s.on_request(ctx) is False
    assert "SUPER-SECRET-XYZZY" not in capsys.readouterr().out


def test_on_response_error_message_is_sanitized(capsys):
    """A failing on_response raises ScriptResponseError carrying only a coarse
    reason -- the underlying error message (which could be `fail(secret())`) must
    not surface in the raised exception or on stdout, where the addon logs it."""
    from starlark_runtime import ScriptResponseError
    s = ScriptedScheme("boom", 'def on_response():\n    fail("DETAIL-LEAK-12345")\n')
    rc, _ = _resp_ctx()
    with pytest.raises(ScriptResponseError) as ei:
        s.on_response(rc)
    assert "DETAIL-LEAK-12345" not in str(ei.value)
    assert "DETAIL-LEAK-12345" not in capsys.readouterr().out


def test_primitive_outside_hook_raises_not_silent():
    """A request primitive called at module top-level (no ctx bound) fails to
    load loudly rather than reading a stale ctx."""
    with pytest.raises(starlark.StarlarkError):
        ScriptedScheme("top", "x = req_header('X')\ndef on_request():\n    return True\n")


def test_missing_on_response_is_noop():
    s = _scripted("bearer")  # defines only on_request
    ctx, _ = _ctx(headers={"Authorization": "Bearer PH"})
    assert s.on_response(ctx) is False


# ---- Python vs Starlark micro-benchmark --------------------------------------

def test_bearer_python_vs_starlark_benchmark():
    """Report per-call cost of the Python built-in vs the Starlark dogfood, and
    guard against a pathological regression. Run with `-s` to see the numbers."""
    py = schemes.SCHEMES["bearer"]
    st = _scripted("bearer")
    N = 500

    def bench(scheme):
        ctxs = [_ctx(headers={"Authorization": "Bearer PH"},
                     params={"header": "Authorization"})[0] for _ in range(N)]
        start = time.perf_counter()
        for c in ctxs:
            scheme.on_request(c)
        return (time.perf_counter() - start) / N

    bench(st)  # warm up the interpreter
    py_per = bench(py)
    st_per = bench(st)
    print(f"\n[bench] bearer  python={py_per * 1e6:6.1f}us/call  "
          f"starlark={st_per * 1e6:6.1f}us/call  ratio={st_per / py_per:5.1f}x")
    # A scripted call (interpreter eval, run inline) should still be well under a
    # millisecond; this loose ceiling only catches pathological regressions
    # (it must tolerate a loaded CI runner).
    assert st_per < 0.1


# ---- runaway-cancellation deadline -------------------------------------------
# A CPU-bound script can't be preempted by a Python-thread timeout (the GIL is
# held for the whole eval). The real mechanism is starlark-pyo3's
# check_cancelled (PR #51), which we feature-detect on the call path. Until it
# lands+releases there, a non-terminating script hangs the proxy (documented).
# Here we unit-test the deadline callback itself.

def test_make_deadline_cancel_fires_past_deadline():
    from starlark_runtime import make_deadline_cancel
    cancel = make_deadline_cancel(timeout_seconds=0.0, check_every=4)
    results = [cancel() for _ in range(8)]
    assert any(results)          # fires once the sample interval is hit
    assert results[-1] is True   # stays cancelled
    assert cancel.fired is True  # records the trip (for accurate logging)


def test_make_deadline_cancel_holds_before_deadline():
    from starlark_runtime import make_deadline_cancel
    cancel = make_deadline_cancel(timeout_seconds=60.0, check_every=4)
    assert not any(cancel() for _ in range(8))
    assert cancel.fired is False


def test_call_cancel_support_is_a_bool():
    import starlark_runtime
    # Whether FrozenModule.call accepts check_cancelled yet (the call-path
    # extension + a release); just assert the feature flag is well-formed so
    # detection can't crash.
    assert isinstance(starlark_runtime._CALL_SUPPORTS_CANCEL, bool)


def test_leading_underscore_functions_are_not_exported():
    """Starlark does not export leading-underscore names on freeze(), so .call
    can't reach them -- the reason on_request/on_response (and the cancel-
    detection probe) must NOT start with '_'. Guards the gotcha that silently
    broke _detect_call_cancel."""
    m = starlark.Module()
    starlark.eval(m, starlark.parse(
        "t.star", "def shown():\n    return True\ndef _hidden():\n    return True\n"
    ), starlark.Globals.standard())
    fm = m.freeze()
    assert fm.call("shown") is True
    with pytest.raises(starlark.StarlarkError):
        fm.call("_hidden")


def test_api_version_constant():
    import starlark_runtime
    assert starlark_runtime.API_VERSION in starlark_runtime.SUPPORTED_API_VERSIONS


# ---- primitive hardening -----------------------------------------------------

def test_jwt_encode_sign_rejects_lying_alg():
    """The primitive always RS256-signs, so a header asking for a different alg
    (the alg:none / HS256-confusion footgun) is rejected."""
    from starlark_runtime import _jwt_encode_sign
    with pytest.raises(ValueError, match="RS256"):
        _jwt_encode_sign({"alg": "none"}, {"sub": "x"}, "unused-pem")


def test_jwt_encode_sign_forces_rs256_header():
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from starlark_runtime import _jwt_encode_sign
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    tok = _jwt_encode_sign({"typ": "JWT"}, {"sub": "x"}, pem)   # no alg given
    h = tok.split(".")[0]
    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert hdr["alg"] == "RS256" and hdr["typ"] == "JWT"


def test_b64decode_rejects_non_alphabet():
    from starlark_runtime import _b64decode
    with pytest.raises(Exception):
        _b64decode("ab*cd==")          # '*' isn't a base64 character
