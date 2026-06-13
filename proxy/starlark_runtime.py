"""Sandboxed Starlark runtime for scripted injection schemes (design-v3).

A *scripted scheme* is the escape hatch for the long tail: a `.star` file that
defines `on_request(ctx)` (and optionally `on_response(ctx)`) and composes the
trusted primitives the proxy provides. It runs IN the proxy, with access to the
real credential via `secret()`, so it is sandboxed -- unlike providers, which
run on the host in the user's own context.

Why this is safe (the door model):
- The script can only act through the registered primitives; it receives the
  request as an `OpaquePythonObject` it cannot introspect (it reappears as the
  real ctx only when handed back to a primitive).
- `Globals.standard()` is the entire global surface -- the Starlark language has
  no I/O, no filesystem, no network, no `import`/`exec`. `load()` is neutralized
  (no FileLoader is passed), so a script can't pull in other files.
- The crypto/encoding primitives are owned and trusted here; scripts orchestrate
  them but never implement crypto.
- Host-scoping lives in the binding, outside the script, so even a shared
  third-party injector can't choose a destination or exfiltrate the secret.

Non-exfiltration, concretely: `Globals.standard()` has no `print`, and a script
error message is NEVER logged (only the exception type is) -- otherwise a script
could `fail(secret(ctx))` and leak the value to proxy stdout. The only data
channel a script has is the request itself, which is already host-scoped to the
binding's destination.

**Runaway scripts (the real resource-bounds gap).** A Python-thread timeout
CANNOT preempt a CPU-bound script: starlark-pyo3 holds the GIL for the whole
evaluation (and exposes no step limit on `FrozenModule.call`), so a thread join
can't return until the script releases the GIL -- which a sandboxed (I/O-free)
script never does mid-compute. The correct mechanism is cooperative
cancellation: `check_cancelled` (starlark-pyo3 PR #51) fires a callback every
~1000 bytecode instructions and aborts when it returns True, so a deadline can
actually interrupt a runaway. PR #51 adds it to `eval()` but not yet to
`FrozenModule.call` (which our hot path uses). We therefore FEATURE-DETECT
support on `.call` (see `_CALL_SUPPORTS_CANCEL`) and pass a deadline cancel when
present; until that lands+releases, a non-terminating script hangs the proxy
until the container is restarted. That DoS is accepted: scripts are trusted
host-authored control-plane config (like provider executables), and it does not
weaken the sandbox's non-exfiltration / no-I/O guarantees.

This module is proxy-only (it imports `starlark`, present only in the proxy
image). It is not wired into config dispatch yet; design-v3 phase 3b adds the
scripted-injector authoring contract that builds ScriptedScheme from a binding.
"""
from __future__ import annotations

import base64
import re
import time

import starlark

# A real credential injection is sub-millisecond; this is a generous deadline
# that bounds a runaway script ONCE check_cancelled is available on the call
# path (see module docstring).
DEFAULT_TIMEOUT = 2.0

_GLOBALS = starlark.Globals.standard()


def make_deadline_cancel(timeout_seconds: float, check_every: int = 256):
    """A `check_cancelled` callback that aborts evaluation after a wall-clock
    deadline. starlark-pyo3 fires it every ~1000 instructions; to keep the
    clock read cheap it only samples `time.monotonic()` every `check_every`
    fires (a power of two -- larger = coarser but cheaper; 256 ≈ 25-40ms
    response). Once the deadline passes, every subsequent fire returns True."""
    mask = check_every - 1
    end = time.monotonic() + timeout_seconds
    n = [0]
    cancelled = [False]

    def cancel() -> bool:
        n[0] += 1
        if n[0] & mask == 0:
            cancelled[0] = time.monotonic() >= end
        return cancelled[0]

    return cancel


def _detect_call_cancel() -> bool:
    """True if FrozenModule.call accepts a `check_cancelled` kwarg (starlark-pyo3
    PR #51 extended to the call path). Probed once at import; until it lands we
    run calls without an enforceable deadline."""
    try:
        m = starlark.Module()
        starlark.eval(m, starlark.parse("_probe.star",
                                        "def _p(c):\n    return True\n"), _GLOBALS)
        m.freeze().call("_p", starlark.OpaquePythonObject(object()),
                        check_cancelled=lambda: False)
        return True
    except TypeError:
        return False
    except Exception:
        return False  # conservative: any oddity -> treat as unsupported


_CALL_SUPPORTS_CANCEL = _detect_call_cancel()


# ---- trusted primitives ------------------------------------------------------
#
# Each primitive takes the ctx (a RequestCtx, passed by the script as the
# OpaquePythonObject it received) as its first argument, except the pure
# encoding helpers. `secret()` is the only door to the resolved value.

def _header_get(ctx, name):
    return ctx.header_get(name)


def _header_set(ctx, name, value):
    ctx.header_set(name, value)


def _body_text(ctx):
    return ctx.body_text()


def _set_body_text(ctx, text):
    ctx.set_body_text(text)


def _secret(ctx, slot="value"):
    return ctx.secret(slot)


def _placeholder(ctx):
    return ctx.placeholder


def _param(ctx, key, default=None):
    return ctx.params.get(key, default)


def _b64encode(s):
    """Base64-encode a str (UTF-8) -> str."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64decode(s):
    """Base64-decode a str -> str (UTF-8). Raises on invalid input, which the
    caller turns into a fail-closed skip."""
    return base64.b64decode(s).decode("utf-8")


PRIMITIVES = {
    "header_get": _header_get,
    "header_set": _header_set,
    "body_text": _body_text,
    "set_body_text": _set_body_text,
    "secret": _secret,
    "placeholder": _placeholder,
    "param": _param,
    "b64encode": _b64encode,
    "b64decode": _b64decode,
}


_HAS_ON_RESPONSE = re.compile(r"(?m)^def[ \t]+on_response\b")


class ScriptedScheme:
    """A Scheme (duck-typed) whose on_request/on_response logic is a sandboxed
    `.star` script. Metadata (name, family, slots, location) is supplied by the
    caller -- the host CLI declares it (it can't run Starlark); the script
    carries only logic. Compiles once at construction; a syntax error, a
    `load()`, or any disallowed construct raises here so a bad script fails to
    load rather than at request time."""

    def __init__(
        self,
        name: str,
        source: str,
        *,
        family: str = "substitute",
        slots: tuple[str, ...] = ("value",),
        location_kind: str = "header",
        header_default: str | None = "Authorization",
        timeout: float = DEFAULT_TIMEOUT,
        filename: str | None = None,
    ):
        self.name = name
        self.family = family
        self.slots = tuple(slots)
        self.location_kind = location_kind
        self.header_default = header_default
        # Deadline for cooperative cancellation; enforced only when the call
        # path supports check_cancelled (see module docstring).
        self._timeout = timeout
        self._has_on_response = bool(_HAS_ON_RESPONSE.search(source))

        module = starlark.Module()
        for prim_name, fn in PRIMITIVES.items():
            module.add_callable(prim_name, fn)
        ast = starlark.parse(filename or f"{name}.star", source)
        # No file_loader -> load() is rejected; standard globals only.
        starlark.eval(module, ast, _GLOBALS)
        self._frozen = module.freeze()

    def on_request(self, ctx) -> bool:
        return self._invoke("on_request", ctx)

    def on_response(self, ctx) -> bool:
        if not self._has_on_response:
            return False
        return self._invoke("on_response", ctx)

    def _invoke(self, fn_name: str, ctx) -> bool:
        """Run the script function, failing CLOSED on any error (return False,
        log). When the call path supports check_cancelled, a wall-clock deadline
        aborts a runaway; otherwise a non-terminating script hangs the proxy
        (documented ceiling -- a Python-thread timeout can't preempt the GIL).

        The error is logged by EXCEPTION TYPE ONLY -- never its message --
        because a script could `fail(secret(ctx))` and the message would carry
        the real credential to stdout, defeating the non-exfiltration guarantee.
        """
        opaque = starlark.OpaquePythonObject(ctx)
        try:
            if _CALL_SUPPORTS_CANCEL:
                result = self._frozen.call(
                    fn_name, opaque,
                    check_cancelled=make_deadline_cancel(self._timeout),
                )
            else:
                result = self._frozen.call(fn_name, opaque)
        except Exception as e:  # StarlarkError / primitive error / deadline abort
            print(f"[script] {self.name}.{fn_name} raised {type(e).__name__}; "
                  f"failing closed", flush=True)
            return False
        return bool(result)
