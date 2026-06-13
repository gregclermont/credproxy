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

The one gap (no step/fuel limit is exposed by starlark-pyo3): each call runs in
a thread with a timeout and the flow FAILS CLOSED on overrun -- a runaway is a
recoverable DoS of one workspace's proxy, never an exfiltration.

This module is proxy-only (it imports `starlark`, present only in the proxy
image). It is not wired into config dispatch yet; design-v3 phase 3b adds the
scripted-injector authoring contract that builds ScriptedScheme from a binding.
"""
from __future__ import annotations

import base64
import concurrent.futures
import re

import starlark

# A real credential injection is sub-millisecond; this is a generous ceiling
# that bounds a runaway script's effect on the proxy.
DEFAULT_TIMEOUT = 2.0

_GLOBALS = starlark.Globals.standard()

# Shared executor purely to impose a per-call deadline. Calls are effectively
# serial (the addon hook blocks awaiting the result), so a few workers suffice.
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="starlark"
)


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
        """Run the script function under a timeout, failing CLOSED on any error
        or overrun (return False, log). The orphaned worker thread on a timeout
        is the documented recoverable-DoS ceiling."""
        future = _EXECUTOR.submit(
            self._frozen.call, fn_name, starlark.OpaquePythonObject(ctx)
        )
        try:
            return bool(future.result(timeout=self._timeout))
        except concurrent.futures.TimeoutError:
            print(
                f"[script] {self.name}.{fn_name} exceeded {self._timeout}s; "
                f"failing closed (request left unmodified)",
                flush=True,
            )
            return False
        except Exception as e:  # StarlarkError, host-primitive error, ...
            print(f"[script] {self.name}.{fn_name} failed: {e}", flush=True)
            return False
