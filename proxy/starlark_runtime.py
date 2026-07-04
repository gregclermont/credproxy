"""Sandboxed Starlark runtime for scripted injection schemes.

A *scripted scheme* is the escape hatch for the long tail: a `.star` file that
defines `on_request()` (and optionally `on_response()`) and composes the trusted
primitives the proxy provides. It runs IN the proxy, with access to the real
credential via `secret()`, so it is sandboxed -- unlike providers, which run on
the host in the user's own context.

The API shape ("option B"): primitives are FLAT top-level functions
with the ctx passed IMPLICITLY. A hook is zero-arg (`def on_request():`); the
runtime binds the current ctx to a contextvar around the call and the primitives
read it. So a script never threads or even holds a ctx handle -- it just calls
`req_header(name)`, `secret()`, `req_set_header(name, value)`. Request-scoped
primitives are prefixed `req_`/`resp_`; the prefix also encodes the phase
(calling `resp_*` in `on_request` raises). Pure helpers (`b64encode`, `crypto`,
`jwt_*`, `json_*`) take no ctx.

Why this is safe (the door model):
- The script has NO handle to the request at all -- it can only act through the
  registered primitives, which reach the real ctx via a contextvar the runtime
  controls. There is nothing to introspect or smuggle out.
- `Globals.standard()` is the entire global surface -- the Starlark language has
  no I/O, no filesystem, no network, no `import`/`exec`. `load()` is neutralized
  (no FileLoader is passed), so a script can't pull in other files.
- The crypto/encoding primitives are owned and trusted here; scripts orchestrate
  them but never implement crypto.
- Host-scoping lives in the binding, outside the script, so even a shared
  third-party injector can't choose a destination or exfiltrate the secret.

Non-exfiltration, concretely: `Globals.standard()` has no `print`, and a script
error message is NEVER logged (only the exception type/a coarse reason is) --
otherwise a script could `fail(secret())` and leak the value to proxy stdout (or
via a raised error). The script's outbound data channel is the request, which is
already host-scoped to the binding's destination. on_response can also mutate the
RESPONSE (the re-seal seam), a channel that points back at the workspace -- so
`secret()` and the request-CONTENT reads (`req_header`/`req_body`/`req_body_b64`)
are request-phase ONLY: the durable secret is unreachable in on_response and so
can't be copied into the response. A re-seal script that fails to scrub its
on_response (any error) fails CLOSED -- the addon withholds the response rather
than forward a body that may still carry the real minted token.

**Runaway scripts (the real resource-bounds gap).** A Python-thread timeout
CANNOT preempt a CPU-bound script: starlark-pyo3 holds the GIL for the whole
evaluation, so a thread join can't return until the script releases the GIL --
which a sandboxed (I/O-free) script never does mid-compute. The correct mechanism
is cooperative cancellation: `check_cancelled` (starlark-pyo3 PR #51) fires a
callback every ~1000 bytecode instructions and aborts when it returns True, so a
deadline can actually interrupt a runaway. PR #51 adds it to `eval()` but not yet
to `FrozenModule.call` (our hot path). We therefore FEATURE-DETECT support on
`.call` (see `_CALL_SUPPORTS_CANCEL`) and pass a deadline cancel when present;
until that lands+releases, a non-terminating script hangs the proxy until the
container is restarted. That DoS is accepted: scripts are trusted host-authored
control-plane config (like provider executables), and it does not weaken the
sandbox's non-exfiltration / no-I/O guarantees.

This module is proxy-only (it imports `starlark`, present only in the proxy
image). `config.load_resolved` builds a ScriptedScheme for each `scheme="script"`
binding from the pushed source + declared metadata.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import json
import re
import time

import starlark

# The primitive API version this runtime implements. A scripted injector's
# manifest declares `api = N`; config rejects a binding whose version this
# runtime does not support. Bump on any breaking change to the primitive set.
API_VERSION = 1
SUPPORTED_API_VERSIONS = frozenset({1})

# A real credential injection is sub-millisecond; this is a generous deadline
# that bounds a runaway script ONCE check_cancelled is available on the call
# path (see module docstring).
DEFAULT_TIMEOUT = 2.0

_GLOBALS = starlark.Globals.standard()

# The current ctx (a RequestCtx or ResponseCtx), bound by `_invoke` for the
# duration of one hook call and read by the stateful primitives. A contextvar
# (not a bare global) so the binding is correct even if calls ever interleave;
# the eval holds the GIL and runs inline on this thread, so a value set here is
# visible to every primitive the script calls and gone again afterwards.
_ctx_var: contextvars.ContextVar = contextvars.ContextVar("scripted_ctx")


def _ctx():
    try:
        return _ctx_var.get()
    except LookupError:
        # A request/response primitive called at module top-level (during load),
        # not inside a hook. Fail loudly rather than silently.
        raise RuntimeError("request primitive called outside on_request/on_response")


def _require(phase: str, fn: str):
    c = _ctx()
    if c.phase != phase:
        raise RuntimeError(f"{fn}() is {phase}-phase only")
    return c


class make_deadline_cancel:
    """A `check_cancelled` callback (callable) that aborts evaluation after a
    wall-clock deadline. starlark-pyo3 fires it every ~1000 instructions; to
    keep the clock read cheap it only samples `time.monotonic()` every
    `check_every` fires (a power of two -- larger = coarser but cheaper; 256 ≈
    25-40ms response). Once the deadline passes, every subsequent fire returns
    True. `.fired` records whether the deadline tripped, so the caller can tell
    a timeout abort from an ordinary script error (both surface as
    StarlarkError)."""

    def __init__(self, timeout_seconds: float, check_every: int = 256):
        self._mask = check_every - 1
        self._end = time.monotonic() + timeout_seconds
        self._n = 0
        self.fired = False

    def __call__(self) -> bool:
        self._n += 1
        if self._n & self._mask == 0 and time.monotonic() >= self._end:
            self.fired = True
        return self.fired


def _detect_call_cancel() -> bool:
    """True if FrozenModule.call accepts a `check_cancelled` kwarg (starlark-pyo3
    extended to the call path; eval-cancel-and-stack-limit). Probed once at
    import; until it lands+releases we run calls without an enforceable deadline.

    The probe function must NOT start with `_`: Starlark treats leading-underscore
    names as module-private, so they are not exported on freeze() and `.call`
    raises 'symbol not exported'. (`on_request`/`on_response` are fine.)"""
    try:
        m = starlark.Module()
        starlark.eval(m, starlark.parse("probe.star",
                                        "def probe():\n    return True\n"), _GLOBALS)
        m.freeze().call("probe", check_cancelled=lambda: False)
        return True
    except TypeError:
        return False  # no check_cancelled kwarg -> unsupported
    except Exception:
        return False  # conservative: any oddity -> treat as unsupported


_CALL_SUPPORTS_CANCEL = _detect_call_cancel()


# ---- trusted primitives ------------------------------------------------------
#
# Stateful primitives read the implicit ctx (a RequestCtx/ResponseCtx) bound to
# `_ctx_var` for the current hook. Request METADATA reads (`req_method`/
# `req_path`/`req_host`) work in both phases; request CONTENT reads
# (`req_header`/`req_body`/`req_body_b64`) and `secret()` are request-phase ONLY
# (in on_response they would expose the injected secret to the response channel);
# request mutation is request-phase only; `resp_*` is response-phase only. Pure
# helpers take no ctx. `secret()` is the only door to the resolved value.

# -- credential / binding --
def _secret(slot="value"):
    # Request-phase ONLY: the durable secret must never be reachable in
    # on_response, where it could be written into the response the workspace
    # receives (resp_set_*). on_response re-seals the minted token from the
    # RESPONSE body and never needs the durable secret.
    return _require("request", "secret").secret(slot)


def _param(key, default=None):
    return _ctx().params.get(key, default)


def _placeholder():
    return _ctx().placeholder


# -- request METADATA reads (both phases): method/path/host carry no secret, so
#    on_response may read them to know which endpoint it answered. --
def _req_method():
    c = _ctx()
    return c.method if c.phase == "request" else c.request_method


def _req_path():
    c = _ctx()
    return c.path if c.phase == "request" else c.request_path


def _req_host():
    c = _ctx()
    return c.host if c.phase == "request" else c.request_host


# -- request CONTENT reads (request phase ONLY): in on_response these would read
#    the request AS SENT -- which on_request injected the real secret into -- so
#    a script could copy it back into the response (resp_set_*) and leak it to
#    the workspace. The phase guard closes that channel. --
def _req_header(name):
    return _require("request", "req_header").header_get(name)


def _req_body():
    return _require("request", "req_body").body_text()


def _req_body_b64():
    raw = _require("request", "req_body_b64").body_bytes()
    return base64.b64encode(raw).decode("ascii")


# -- request mutation (request phase only) --
def _req_set_header(name, value):
    _require("request", "req_set_header").header_set(name, value)


def _req_set_body(text):
    _require("request", "req_set_body").set_body_text(text)


# -- response (response phase only) --
def _resp_status():
    return _require("response", "resp_status").status_code


def _resp_header(name):
    return _require("response", "resp_header").header_get(name)


def _resp_set_header(name, value):
    _require("response", "resp_set_header").header_set(name, value)


def _resp_body():
    return _require("response", "resp_body").body_text()


def _resp_set_body(text):
    _require("response", "resp_set_body").set_body_text(text)


def _resp_json():
    """The response body parsed as JSON, or None if the body is absent or not
    valid JSON (the common "is this the token endpoint?" branch -- total, so the
    script can test it with `== None` rather than needing try/except)."""
    c = _require("response", "resp_json")
    text = c.body_text()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


# -- re-seal: mint a dynamic placeholder for a runtime-derived secret. The API
#    hosts and target header come from the binding params (`api_hosts`,
#    `reseal_header`), so the script just supplies the value + TTL. --
def _mint(value, ttl):
    """Register a runtime swap (placeholder -> value) on the binding's api_hosts
    with `ttl` seconds, and return the placeholder."""
    c = _require("response", "mint")
    return c.mint(value, int(ttl), c.params.get("api_hosts"),
                  c.params.get("reseal_header", "Authorization"))


def _mint_into_json(field, value, ttl):
    """mint(value, ttl), then rewrite the response body's JSON `field` to the
    placeholder so the workspace receives the placeholder, not the real token."""
    c = _require("response", "mint_into_json")
    return c.mint_into_json(field, value, int(ttl), c.params.get("api_hosts"),
                            c.params.get("reseal_header", "Authorization"))


# -- encoding (text <-> encoding; every encode has a decode) --
def _b64encode(s):
    """Base64-encode a str (UTF-8) -> str."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64decode(s):
    """Base64-decode a str -> str (UTF-8). `validate=True` so non-alphabet bytes
    are REJECTED rather than silently ignored -- a malformed carrier (e.g. a
    Basic blob with stray punctuation) fails closed instead of decoding to
    something unintended."""
    return base64.b64decode(s, validate=True).decode("utf-8")


def _b64url_encode(s):
    """URL-safe base64 with padding stripped (the JWT/JWS encoding)."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).rstrip(b"=").decode("ascii")


def _b64url_decode(s):
    """Inverse of b64url_encode: accepts unpadded URL-safe base64 -> str."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")


# -- carrier transcode: re-encode raw bytes between base64 and hex without a
#    UTF-8 round-trip. The bridge that lets carrier-form crypto (below) end in a
#    hex signature, e.g. AWS SigV4's `hex(hmac(signing_key, string_to_sign))`. --
def _b64_to_hex(b64):
    return base64.b64decode(b64).hex()


def _hex_to_b64(h):
    return base64.b64encode(bytes.fromhex(h)).decode("ascii")


# -- hashing / MAC. hmac_sha256 is CARRIER form: the key is base64 of raw key
#    bytes and the output is base64 of the raw MAC, so multi-round key
#    derivations (AWS SigV4) can chain output -> next key. The *_hex helpers
#    cover the common single-shot case (OVH sha1, simple HMAC). Crypto stays
#    host-owned; scripts only assemble the signing input. --
def _hmac_sha256(key_b64, msg):
    key = base64.b64decode(key_b64)
    return base64.b64encode(hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")


def _sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _sha1_hex(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _hmac_sha256_hex(key, msg):
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _rs256_sign(private_key_pem, msg):
    """RS256 (RSASSA-PKCS1-v1_5 over SHA-256): sign `msg` with the PEM RSA
    private key, return the signature as unpadded base64url (the JWT/JWS form)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    sig = key.sign(msg.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


# -- JWT/JWS: assembling the three segments (header.claims.signature) by hand is
#    the classic footgun (segment order, padding, signing the right bytes), so
#    the proxy owns it. --
def _jwt_encode_sign(header, claims, private_key_pem):
    """Build a signed RS256 JWS compact token from header/claims dicts. The
    header's `alg` is FORCED to RS256 -- the only algorithm this primitive
    implements -- so a script can't emit a header that lies about the signature
    (the classic `alg:none`/`HS256`-confusion footgun); a header that explicitly
    asks for a different alg is rejected."""
    alg = header.get("alg")
    if alg is not None and alg != "RS256":
        raise ValueError(f"jwt_encode_sign signs RS256 only, not alg={alg!r}")
    header = {**header, "alg": "RS256"}
    seg = (_b64url_encode(json.dumps(header, separators=(",", ":"))) + "."
           + _b64url_encode(json.dumps(claims, separators=(",", ":"))))
    return seg + "." + _rs256_sign(private_key_pem, seg)


def _jwt_decode_or_none(token):
    """The JWT claims (middle segment) as a dict, or None if `token` is not a
    well-formed JWT. Does NOT verify the signature -- for reading a token the
    proxy is re-sealing, not trusting."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None


# -- JSON --
def _json_encode(value):
    """Compact, deterministic JSON for a Starlark value (dict/list/str/int/bool/
    None) -- e.g. building a JWT header/claims set. Keys keep insertion order."""
    return json.dumps(value, separators=(",", ":"))


def _json_decode(s):
    """Parse a JSON string to a Starlark value. Raises on invalid input (the
    caller turns that into a fail-closed skip)."""
    return json.loads(s)


# -- time --
def _now():
    """Current Unix time (seconds). A trusted primitive because the sandbox has
    no clock -- needed by time-bound signatures (OVH timestamp, JWT iat/exp)."""
    return int(time.time())


def _now_ms():
    """Current Unix time in milliseconds."""
    return int(time.time() * 1000)


# -- rule terminal sinks (kind="rule" only). They record a synthetic response on
#    the implicit ctx (a rules.RuleRequestCtx/RuleResponseCtx); the addon reads
#    `ctx.pending` and short-circuits. A rule script has no secret to protect, so
#    these are plain and their failures surface fully. --
def _block(status=403, reason=None):
    """Terminate the flow with a policy block (status, default 403)."""
    _ctx().block(int(status), reason)


def _respond(status, body="", headers=None):
    """Terminate the flow with an author-supplied response (status, body,
    headers)."""
    _ctx().respond(int(status), body, headers)


PRIMITIVES = {
    # credential / binding
    "secret": _secret,
    "param": _param,
    "placeholder": _placeholder,
    # request reads (both phases)
    "req_method": _req_method,
    "req_path": _req_path,
    "req_host": _req_host,
    "req_header": _req_header,
    "req_body": _req_body,
    "req_body_b64": _req_body_b64,
    # request mutation (request phase)
    "req_set_header": _req_set_header,
    "req_set_body": _req_set_body,
    # response (response phase)
    "resp_status": _resp_status,
    "resp_header": _resp_header,
    "resp_set_header": _resp_set_header,
    "resp_body": _resp_body,
    "resp_set_body": _resp_set_body,
    "resp_json": _resp_json,
    # re-seal (response phase)
    "mint": _mint,
    "mint_into_json": _mint_into_json,
    # encoding
    "b64encode": _b64encode,
    "b64decode": _b64decode,
    "b64url_encode": _b64url_encode,
    "b64url_decode": _b64url_decode,
    "b64_to_hex": _b64_to_hex,
    "hex_to_b64": _hex_to_b64,
    # hashing / signing
    "hmac_sha256": _hmac_sha256,
    "sha256_hex": _sha256_hex,
    "sha1_hex": _sha1_hex,
    "hmac_sha256_hex": _hmac_sha256_hex,
    "rs256_sign": _rs256_sign,
    "jwt_encode_sign": _jwt_encode_sign,
    "jwt_decode_or_none": _jwt_decode_or_none,
    # json / time
    "json_encode": _json_encode,
    "json_decode": _json_decode,
    "now": _now,
    "now_ms": _now_ms,
}


# The restricted primitive set for kind="rule" scripts. A rule governs traffic
# but never touches a credential, so this profile OMITS every secret-bearing and
# crypto/carrier primitive (see FORBIDDEN_RULE_PRIMITIVES) and ADDS the terminal
# `block`/`respond` sinks. Because a rule script physically cannot reach secret
# material, its errors are NOT sanitized (unlike injector scripts) -- a real
# authoring-UX win (#26).
_RULE_PRIMITIVE_NAMES = (
    # request metadata (both phases) + content reads + mutation
    "req_method", "req_path", "req_host",
    "req_header", "req_body", "req_body_b64",
    "req_set_header", "req_set_body",
    # response reads + mutation
    "resp_status", "resp_header", "resp_set_header",
    "resp_body", "resp_set_body", "resp_json",
    # inert encoding + json + time + read-only jwt claims inspection
    "b64encode", "b64decode", "b64url_encode", "b64url_decode",
    "json_encode", "json_decode", "now", "now_ms", "jwt_decode_or_none",
)

RULE_PRIMITIVES = {
    **{name: PRIMITIVES[name] for name in _RULE_PRIMITIVE_NAMES},
    # terminal sinks (rule-only)
    "block": _block,
    "respond": _respond,
}

# Credential-bearing primitives a rule may not reach. They are simply ABSENT
# from RULE_PRIMITIVES (the real guard), so starlark-rust's name resolver rejects
# a rule that references one at CONSTRUCTION -- `Variable `secret` not found` --
# with no source scan needed (verified in-image). This set only lets us turn that
# resolver error into a targeted hint (see _rule_compile_hint) instead of a raw
# "variable not found". Covers the credential door (`secret`), the re-seal mints,
# and the crypto/carrier primitives.
FORBIDDEN_RULE_PRIMITIVES = frozenset({
    "secret", "mint", "mint_into_json",
    "hmac_sha256", "hmac_sha256_hex", "sha256_hex", "sha1_hex",
    "rs256_sign", "jwt_encode_sign", "b64_to_hex", "hex_to_b64",
})

_MISSING_VAR_RE = re.compile(r"Variable `([^`]+)` not found")


def _rule_compile_hint(err: Exception) -> str | None:
    """If a rule failed to compile because it referenced a credential-bearing
    primitive absent from RULE_PRIMITIVES, return a targeted message; else None
    (the raw compile error is surfaced -- it's unsanitized for rule scripts)."""
    m = _MISSING_VAR_RE.search(str(err))
    if m and m.group(1) in FORBIDDEN_RULE_PRIMITIVES:
        return (f"rule script may not use '{m.group(1)}': a rule governs traffic "
                f"but can never touch credential material (the secret/mint/crypto "
                f"primitives are unavailable in rule scripts)")
    return None


def _module_defines(source: str, name: str, primitives: dict, filename: str) -> bool:
    """True iff `source` binds a TOP-LEVEL callable `name` (a hook). Uses the real
    Starlark resolver, NOT a lexer: compile a throwaway module of `source` plus a
    probe that references `name` and asserts it is a function. Three ways to be
    False, all as an eval error the caller catches:
      - `name` is undefined -> the resolver raises `Variable `name` not found`;
      - `name` is a non-callable binding (e.g. `on_request = True`) -> the
        `type(...) == "function"` guard's `else fail(...)` fires (else the runtime
        would later `call()` a non-callable and 502 every matching request);
      - (a `def` inside a docstring / a `\"\"\"` in a single-quoted literal are
        simply not bindings -- the cases that fooled the old `(?m)^def` regex).
    A conditional EXPRESSION, not an `if` statement (Starlark forbids top-level
    `if`). `type(fn)` is `"function"` for both `def`s and lambdas, so a real
    `on_request = <fn>` alias correctly counts. The probe only binds/inspects the
    object; it never calls it. `source` compiled clean first, so the ONLY new
    failure is the probe itself."""
    module = starlark.Module()
    for prim_name, fn in primitives.items():
        module.add_callable(prim_name, fn)
    probe = (f"{source}\n_credproxy_probe = ({name} if type({name}) == "
             f'"function" else fail("{name} is not a function"))\n')
    try:
        starlark.eval(module, starlark.parse(filename, probe), _GLOBALS)
        return True
    except Exception:
        return False


class ScriptResponseError(Exception):
    """Raised by a scripted scheme's on_response when the hook fails, so the
    addon FAILS CLOSED (withholds the response) instead of forwarding a body that
    may still carry the real minted token. The message carries only the
    scheme/hook name and a coarse reason -- NEVER the underlying error message,
    which could be `fail(secret())` and leak the credential to proxy stdout."""


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
        kind: str = "inject",
        family: str = "substitute",
        slots: tuple[str, ...] = ("value",),
        location_kind: str = "header",
        header_default: str | None = "Authorization",
        timeout: float = DEFAULT_TIMEOUT,
        filename: str | None = None,
    ):
        self.name = name
        # kind="inject" -> a scripted injection scheme (full primitives, secret
        # access, sanitized errors). kind="rule" -> a traffic-governance rule
        # (restricted primitives, no secret, block/respond sinks, FULL errors).
        self.kind = kind
        self.family = family
        self.slots = tuple(slots)
        self.location_kind = location_kind
        self.header_default = header_default
        # Deadline for cooperative cancellation; enforced only when the call
        # path supports check_cancelled (see module docstring).
        self._timeout = timeout

        # kind picks the primitive set; credential-bearing primitives are simply
        # absent from RULE_PRIMITIVES, so the resolver rejects a rule that
        # references one (no source scan needed).
        primitives = RULE_PRIMITIVES if kind == "rule" else PRIMITIVES
        fname = filename or f"{name}.star"
        module = starlark.Module()
        for prim_name, fn in primitives.items():
            module.add_callable(prim_name, fn)
        # No file_loader -> load() is rejected; standard globals only. starlark's
        # name resolver rejects any reference to an unregistered name here, so a
        # rule calling a credential primitive (secret/mint/crypto) fails to
        # compile; translate that into a targeted hint.
        try:
            starlark.eval(module, starlark.parse(fname, source), _GLOBALS)
        except Exception as e:
            if kind == "rule":
                hint = _rule_compile_hint(e)
                if hint is not None:
                    raise ValueError(hint) from e
            raise
        self._frozen = module.freeze()

        # Which hooks the script actually defines -- via the resolver (see
        # _module_defines), not a lexer. `source` compiled clean above, so each
        # probe's only new failure mode is an undefined reference to the hook.
        self._has_on_request = _module_defines(source, "on_request", primitives, fname)
        self._has_on_response = _module_defines(source, "on_response", primitives, fname)
        if kind == "rule" and not self._has_on_request and not self._has_on_response:
            raise ValueError(
                "rule script defines neither on_request() nor on_response()")

    @property
    def mutates_response(self) -> bool:
        # A script with an on_response is treated as response-mutating: on a hook
        # error the addon must withhold the (possibly token-bearing) response.
        return self._has_on_response

    @property
    def has_on_request(self) -> bool:
        """Whether the script defines on_request (used by the rules layer to
        decide if a scripted rule runs in the request phase)."""
        return self._has_on_request

    @property
    def has_on_response(self) -> bool:
        """Whether the script defines on_response (used by the rules layer to
        decide if a scripted rule runs in the response phase)."""
        return self._has_on_response

    def on_request(self, ctx) -> bool:
        if self.kind == "rule":
            # A response-only rule has no request-phase effect: no-op rather than
            # calling a non-exported symbol.
            if not self._has_on_request:
                return False
            # A rule holds no secret, so a failing hook is surfaced in full and
            # RAISES so the addon fails closed toward the policy (a 502).
            return self._invoke("on_request", ctx, raise_on_error=True,
                                 sanitize=False)
        return self._invoke("on_request", ctx)

    def on_response(self, ctx) -> bool:
        if not self._has_on_response:
            return False
        if self.kind == "rule":
            return self._invoke("on_response", ctx, raise_on_error=True,
                                 sanitize=False)
        # Response-phase failure must NOT forward the (possibly token-bearing)
        # response: raise so the addon fails closed. (on_request failure is safe
        # to swallow -- the request just proceeds un-injected.)
        return self._invoke("on_response", ctx, raise_on_error=True)

    def extra_intercept_hosts(self, params) -> list:
        """A scripted re-seal injector declares the API hosts it mints onto via
        the `api_hosts` param; they must be TLS-terminated so the runtime swap
        applies (parity with the built-in oauth2-reseal scheme)."""
        hosts = params.get("api_hosts") or []
        return [h for h in hosts if isinstance(h, str) and h]

    def _invoke(self, fn_name: str, ctx, raise_on_error: bool = False,
                sanitize: bool = True) -> bool:
        """Run the script hook. Binds `ctx` to the contextvar for the duration of
        the call so the flat primitives can reach it, then always unbinds. When
        the call path supports check_cancelled, a wall-clock deadline aborts a
        runaway; otherwise a non-terminating script hangs the proxy (documented
        ceiling -- a Python-thread timeout can't preempt the GIL).

        On error: with `raise_on_error` (the response phase) we raise a SANITIZED
        ScriptResponseError so the addon fails CLOSED and withholds the response;
        otherwise (the request phase) we fail closed by returning False (the
        request just proceeds un-injected).

        The error is surfaced by EXCEPTION TYPE / a coarse reason ONLY -- never
        the underlying message -- because a script could `fail(secret())` and the
        message would carry the real credential (to stdout, or via the raised
        error) and defeat the non-exfiltration guarantee.
        """
        cancel = make_deadline_cancel(self._timeout) if _CALL_SUPPORTS_CANCEL else None
        token = _ctx_var.set(ctx)
        try:
            try:
                if cancel is not None:
                    result = self._frozen.call(fn_name, check_cancelled=cancel)
                else:
                    result = self._frozen.call(fn_name)
            except Exception as e:  # StarlarkError / primitive error / deadline abort
                timed_out = cancel is not None and cancel.fired
                if not sanitize:
                    # Rule scripts hold no secret, so the FULL message is safe to
                    # surface -- a real authoring-UX win (#26). Raise so the addon
                    # fails closed toward the policy.
                    reason = "deadline exceeded" if timed_out else str(e)
                    raise RuntimeError(
                        f"{self.name}.{fn_name} failed: {reason}") from e
                reason = "deadline" if timed_out else type(e).__name__
                if raise_on_error:
                    # `from None`: drop the chained cause so its (secret-bearing)
                    # message can't surface in a traceback the addon logs.
                    raise ScriptResponseError(
                        f"{self.name}.{fn_name} failed ({reason}); "
                        f"response withheld") from None
                import log
                log.emit("script", scheme=self.name, hook=fn_name, reason=reason,
                         outcome="failing closed")
                return False
            return bool(result)
        finally:
            _ctx_var.reset(token)
