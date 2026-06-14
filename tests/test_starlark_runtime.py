"""Tests for the sandboxed Starlark runtime (proxy/starlark_runtime.py).

The dogfood `.star` re-implementations of bearer/basic/body must behave
IDENTICALLY to the Python built-ins (that's the point of dogfooding), the
sandbox must reject `load()`, errors must fail closed, and a runaway must time
out. A Python-vs-Starlark micro-benchmark reports the per-call cost.
"""
import base64
import time
from pathlib import Path

import pytest
import starlark
from mitmproxy.test import tutils

import schemes
from starlark_runtime import ScriptedScheme

SCRIPTS = (Path(__file__).resolve().parents[1]
           / "cli" / "credproxy_cli" / "bundled" / "scripts")


def _ctx(*, headers=None, body=None, secrets=None, params=None, ph="PH"):
    req = tutils.treq(host="api.github.com", method=b"GET", path=b"/",
                      content=(body.encode() if body is not None else b""))
    req.headers.clear()
    for k, v in (headers or {}).items():
        req.headers[k] = v
    ctx = schemes.RequestCtx(req, secrets or {"value": "REAL"}, params or {}, ph)
    return ctx, req


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


# ---- sandbox + fail-closed + timeout -----------------------------------------

def test_sandbox_rejects_load_at_compile():
    """A script that uses load() can't pull in other files -- it fails to
    compile (no FileLoader is provided)."""
    with pytest.raises(starlark.StarlarkError):
        ScriptedScheme("evil", 'load("other.star", "f")\ndef on_request(ctx):\n    return True\n')


def test_sandbox_has_no_print():
    """print is not in Globals.standard(), so a script can't write to stdout."""
    with pytest.raises(starlark.StarlarkError):
        ScriptedScheme("p", 'def on_request(ctx):\n    print("x")\n    return True\n')


def test_script_runtime_error_fails_closed():
    """A script that errors at run time returns False (request unmodified),
    never raising into the addon."""
    s = ScriptedScheme("boom", 'def on_request(ctx):\n    fail("kaboom")\n')
    ctx, req = _ctx(headers={"Authorization": "Bearer PH"})
    assert s.on_request(ctx) is False
    assert req.headers["Authorization"] == "Bearer PH"  # untouched


def test_script_error_does_not_leak_secret_to_stdout(capsys):
    """A script that does fail(secret(ctx)) must NOT leak the credential to
    proxy stdout -- the runtime logs the exception type only, never its
    message."""
    s = ScriptedScheme("leak", 'def on_request(ctx):\n    fail(secret(ctx))\n')
    ctx, _ = _ctx(secrets={"value": "SUPER-SECRET-XYZZY"})
    assert s.on_request(ctx) is False
    assert "SUPER-SECRET-XYZZY" not in capsys.readouterr().out


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
    # A scripted call (interpreter + thread hop) should still be well under a
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
        "t.star", "def shown(c):\n    return True\ndef _hidden(c):\n    return True\n"
    ), starlark.Globals.standard())
    fm = m.freeze()
    assert fm.call("shown", starlark.OpaquePythonObject(object())) is True
    with pytest.raises(starlark.StarlarkError):
        fm.call("_hidden", starlark.OpaquePythonObject(object()))
