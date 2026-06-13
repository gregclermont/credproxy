"""Injection schemes: the typed, scheme-aware request transforms.

A *scheme* is the proxy-side mechanism that turns a credential into an
outbound request. design-v3 splits schemes into two families:

  - **substitute** — the workspace holds an inert placeholder and sends it;
    the scheme finds it in its wire location and swaps in the real value,
    decoding/re-encoding as the location dictates (`bearer`, `basic`, `body`).
  - **sign** — no usable static value on the wire; the scheme holds a signing
    key and computes auth material per request (`sigv4`, … — added later).

Every scheme — built-in here, or a sandboxed Starlark script later — is
expressed against ONE interface so the two are interchangeable:

  - `on_request(ctx)`  — mutate the outbound request. Returns True if it
    actually changed the request (used only for logging).
  - `on_response(ctx)` — *optional*; mutate the response. Plumbed from day one
    (see addon.response) but a no-op until the re-seal schemes use it.

Schemes never touch the real secret directly: they read it through
`ctx.secret(slot)`, the single door to the resolved value. The crypto and
encoding primitives (the correctness-sensitive code) live here, owned and
trusted; schemes only orchestrate them. That keeps "we own the crypto" while
leaving composition open to scripts.

`SCHEMES` is the registry the config loader dispatches on. Each scheme
declares its `slots` (the secret slot names it consumes); the substitute
family is single-slot ("value"). Adding a scheme is adding one entry here
plus a matching `SchemeSpec` in the CLI's `core/schemes.py` catalog.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Protocol
from urllib.parse import unquote


class _Ctx:
    """Shared context base: the secret door + encoding primitives.

    A scheme reaches the real value only via `secret()` and never sees the
    mitmproxy objects directly (this mirrors the OpaquePythonObject the Starlark
    escape hatch will hand scripts later)."""

    def __init__(self, secrets: dict[str, str], params: dict,
                 placeholder: str | None):
        self._secrets = secrets
        self.params = params
        self.placeholder = placeholder

    # -- the only door to the resolved credential --
    def secret(self, slot: str = "value") -> str:
        try:
            return self._secrets[slot]
        except KeyError:
            raise KeyError(f"no secret slot {slot!r} (have {sorted(self._secrets)})")

    # -- encoding primitives --
    @staticmethod
    def b64encode(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def b64decode(s: str) -> bytes:
        return base64.b64decode(s)


class RequestCtx(_Ctx):
    """The request-phase surface (passed to `on_request`).

    Wraps a mitmproxy request plus this binding's resolved secret slots and
    scheme params; a scheme reads/modifies the request only through these
    primitives.
    """

    def __init__(self, request, secrets: dict[str, str], params: dict,
                 placeholder: str | None):
        super().__init__(secrets, params, placeholder)
        self._req = request

    # -- request line / host (read-only; sign schemes canonicalize over these) --
    @property
    def method(self) -> str:
        return self._req.method

    @property
    def path(self) -> str:
        """The request target as sent: path plus `?query` if present."""
        return self._req.path

    @property
    def host(self) -> str:
        return self._req.host

    # -- header primitives --
    def header_get(self, name: str) -> str | None:
        return self._req.headers.get(name)

    def header_set(self, name: str, value: str) -> None:
        self._req.headers[name] = value

    # -- raw body bytes (sign schemes hash the entity body) --
    def body_bytes(self) -> bytes:
        return self._req.content or b""

    # -- body primitives (text view handles content-encoding transparently) --
    def body_text(self) -> str | None:
        return self._req.text

    def set_body_text(self, text: str) -> None:
        self._req.text = text


class ResponseCtx(_Ctx):
    """The response-phase surface (passed to `on_response`).

    Wraps the whole flow so a re-seal/mint scheme can READ the request it
    answered (host/path/method — to know which binding/endpoint this is) and
    READ or MUTATE the response (e.g. extract a minted token from the body and
    register a dynamic placeholder). Distinct from RequestCtx because the
    request accessors here are read-only and the mutating header/body
    primitives act on the response, not the request.
    """

    def __init__(self, flow, secrets: dict[str, str], params: dict,
                 placeholder: str | None):
        super().__init__(secrets, params, placeholder)
        self._flow = flow

    # -- the request that was sent (read-only) --
    @property
    def request_method(self) -> str:
        return self._flow.request.method

    @property
    def request_path(self) -> str:
        return self._flow.request.path

    @property
    def request_host(self) -> str:
        return self._flow.request.host

    def request_header_get(self, name: str) -> str | None:
        return self._flow.request.headers.get(name)

    # -- the response (read / mutate) --
    @property
    def status_code(self) -> int:
        return self._flow.response.status_code

    def header_get(self, name: str) -> str | None:
        return self._flow.response.headers.get(name)

    def header_set(self, name: str, value: str) -> None:
        self._flow.response.headers[name] = value

    def body_text(self) -> str | None:
        return self._flow.response.text

    def set_body_text(self, text: str) -> None:
        self._flow.response.text = text


class Scheme(Protocol):
    name: str
    family: str
    slots: tuple[str, ...]
    # Where on the wire the scheme writes, used for collision detection. A
    # "header" scheme writes the header named by params["header"] (default
    # `header_default`); a "body" scheme writes the request body. See
    # location_key(); mirrored on the CLI's SchemeSpec.
    location_kind: str
    header_default: str | None

    def on_request(self, ctx: RequestCtx) -> bool: ...
    def on_response(self, ctx: ResponseCtx) -> bool: ...


def location_key(scheme: "Scheme", params: dict) -> tuple:
    """The wire location a scheme writes, as a hashable key. Two bindings that
    return the same key on the same host collide. Data-driven (no per-scheme
    name matching): header schemes key on the resolved header name, others on
    their location_kind."""
    if scheme.location_kind == "header":
        return ("header", params.get("header", scheme.header_default))
    return (scheme.location_kind,)


class _SubstituteScheme:
    """Shared base for the placeholder-driven family: single `value` slot,
    no response phase."""

    family = "substitute"
    slots = ("value",)

    def on_response(self, ctx: ResponseCtx) -> bool:  # noqa: D401 - no-op seam
        return False


class BearerScheme(_SubstituteScheme):
    """Substring-swap the placeholder for the real value inside a named header
    (default `Authorization`). The surrounding format (`Bearer `, `token `, …)
    is already on the wire — the client built the header — so we replace only
    the placeholder substring, never the whole value."""

    name = "bearer"
    location_kind = "header"
    header_default = "Authorization"

    def on_request(self, ctx: RequestCtx) -> bool:
        header = ctx.params.get("header", "Authorization")
        value = ctx.header_get(header)
        if value is None or ctx.placeholder is None or ctx.placeholder not in value:
            return False
        ctx.header_set(header, value.replace(ctx.placeholder, ctx.secret()))
        return True


class BasicScheme(_SubstituteScheme):
    """HTTP Basic decode-and-swap: decode `Authorization: Basic`, replace the
    component equal to the placeholder with the real value, re-encode.

    The placeholder is a BARE token (no hand-computed base64). We swap the
    password component by default — design-v3's decision — but also accept the
    placeholder in the username position, since some services (e.g. GitHub git
    over HTTPS) put the token there with a dummy password. The other component
    comes straight from the wire, so no username config is needed."""

    name = "basic"
    location_kind = "header"
    header_default = "Authorization"

    def on_request(self, ctx: RequestCtx) -> bool:
        header = ctx.params.get("header", "Authorization")
        value = ctx.header_get(header)
        if value is None or ctx.placeholder is None:
            return False
        prefix = "Basic "
        # The auth-scheme token is case-insensitive (RFC 7235), so accept
        # "basic"/"BASIC"; we re-emit canonical "Basic ".
        if value[:len(prefix)].lower() != prefix.lower():
            return False
        try:
            user, sep, pw = ctx.b64decode(value[len(prefix):].strip()) \
                .decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        if sep != ":":
            return False
        if pw == ctx.placeholder:
            pw = ctx.secret()
        elif user == ctx.placeholder:
            user = ctx.secret()
        else:
            return False
        ctx.header_set(header, prefix + ctx.b64encode(f"{user}:{pw}".encode("utf-8")))
        return True


class BodyScheme(_SubstituteScheme):
    """Substring-swap the placeholder for the real value anywhere in the
    request body — for credentials carried in form/JSON bodies (OAuth2
    client-credentials `client_secret=…`, key-in-body APIs). The text view
    transparently handles content-encoding."""

    name = "body"
    location_kind = "body"
    header_default = None

    def on_request(self, ctx: RequestCtx) -> bool:
        text = ctx.body_text()
        if not text or ctx.placeholder is None or ctx.placeholder not in text:
            return False
        ctx.set_body_text(text.replace(ctx.placeholder, ctx.secret()))
        return True


# --------------------------------------------------------------------------
# Sign family
# --------------------------------------------------------------------------
#
# The crypto lives here, owned and trusted; the scheme orchestrates it. AWS
# SigV4 (https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html).

_SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)


def _uri_encode(s: str, *, encode_slash: bool = True) -> str:
    """AWS URI-encode: unreserved chars verbatim, everything else %XX (upper
    hex) over the UTF-8 bytes. `/` is preserved when encode_slash is False."""
    out: list[str] = []
    for ch in s:
        if ch in _UNRESERVED:
            out.append(ch)
        elif ch == "/" and not encode_slash:
            out.append("/")
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def _parse_sigv4_authorization(auth: str) -> dict | None:
    """Pull the credential scope and signed-header list out of an incoming
    `Authorization: AWS4-HMAC-SHA256 Credential=.../date/region/service/
    aws4_request, SignedHeaders=h;..., Signature=...` header. Returns None if
    the header is not a SigV4 header we understand."""
    prefix = _SIGV4_ALGORITHM + " "
    if not auth.startswith(prefix):
        return None
    fields: dict[str, str] = {}
    for seg in auth[len(prefix):].split(","):
        key, _, val = seg.strip().partition("=")
        fields[key.strip()] = val.strip()
    cred = fields.get("Credential", "").split("/")
    if "SignedHeaders" not in fields or len(cred) < 5:
        return None
    return {
        "date": cred[1],
        "region": cred[2],
        "service": cred[3],
        "signed_headers": [h for h in fields["SignedHeaders"].split(";") if h],
    }


def sigv4_resign(
    *,
    method: str,
    path: str,
    host: str,
    header_get,
    body: bytes,
    scope: dict,
    amz_date: str,
    access_key_id: str,
    secret_access_key: str,
) -> str:
    """Recompute the SigV4 canonical request from the live request and the
    incoming credential scope, then return a fresh `Authorization` value signed
    with the real key. The workspace's SDK already chose the SignedHeaders and
    payload hash (signing with throwaway creds); we reproduce its canonical
    request byte-for-byte and only swap the access key id + signature.

    `amz_date` is the full request timestamp the StringToSign is keyed to (the
    caller resolves it from X-Amz-Date / Date)."""
    date, region, service = scope["date"], scope["region"], scope["service"]
    signed = sorted(h.lower() for h in scope["signed_headers"])
    signed_headers_str = ";".join(signed)

    # Canonical URI: the wire path is already encoded once. Non-S3 services
    # encode it again (the notorious double-encode); S3 takes it as-is.
    raw_path = path.split("?", 1)[0] or "/"
    canonical_uri = raw_path if service == "s3" \
        else _uri_encode(raw_path, encode_slash=False)

    # Canonical query string: decode then canonically re-encode each pair,
    # sort by encoded key (then value).
    query = path.split("?", 1)[1] if "?" in path else ""
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        pairs.append((_uri_encode(unquote(k)), _uri_encode(unquote(v))))
    pairs.sort()
    canonical_query = "&".join(f"{k}={v}" for k, v in pairs)

    # Canonical headers: each signed header, lowercased name, trimmed+collapsed
    # value. `host` falls back to the request host if not a real header.
    header_lines = []
    for h in signed:
        val = header_get(h)
        if val is None and h == "host":
            val = host
        val = " ".join((val or "").split())
        header_lines.append(f"{h}:{val}\n")
    canonical_headers = "".join(header_lines)

    # Payload hash: the value the SDK used -- the x-amz-content-sha256 header if
    # it set one (S3, or UNSIGNED-PAYLOAD), else the SHA256 of the body.
    payload_hash = header_get("x-amz-content-sha256") \
        or header_get("X-Amz-Content-Sha256") or _sha256_hex(body)

    canonical_request = "\n".join([
        method, canonical_uri, canonical_query,
        canonical_headers, signed_headers_str, payload_hash,
    ])

    credential_scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        _SIGV4_ALGORITHM, amz_date, credential_scope,
        _sha256_hex(canonical_request.encode("utf-8")),
    ])

    key = _signing_key(secret_access_key, date, region, service)
    signature = hmac.new(key, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    return (
        f"{_SIGV4_ALGORITHM} Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, Signature={signature}"
    )


class SigV4Scheme:
    """AWS Signature Version 4 (sign family). The workspace signs with throwaway
    creds so its SDK produces a SigV4 request; the proxy parses the scope it
    chose, recomputes the canonical request, and re-signs with the real key --
    so the real access/secret key never enters the workspace. region + service
    are read from the request, so no params are needed."""

    name = "sigv4"
    family = "sign"
    slots = ("access_key_id", "secret_access_key")
    # sigv4 rewrites the Authorization header, so it collides with a
    # bearer/basic binding on the same host. It ignores params (region/service
    # come from the request), so the header is always the default.
    location_kind = "header"
    header_default = "Authorization"

    def on_request(self, ctx: RequestCtx) -> bool:
        auth = ctx.header_get("Authorization")
        if not auth:
            return False
        scope = _parse_sigv4_authorization(auth)
        if scope is None:
            return False
        # Temporary (STS) credentials carry X-Amz-Security-Token, which the SDK
        # signs. We re-sign with the binding's LONG-TERM key, which has no
        # session token -- pairing a real key with the workspace's throwaway
        # token always yields a request AWS rejects. Refuse loudly instead of
        # silently emitting a doomed signature.
        if ctx.header_get("x-amz-security-token") is not None:
            print(
                "[sigv4] request carries X-Amz-Security-Token (temporary "
                "credentials); credproxy re-signs with long-term keys only -- "
                "configure the workspace with dummy STATIC AWS credentials "
                "(no session token). Leaving the request unsigned-as-is.",
                flush=True,
            )
            return False
        # The StringToSign is keyed to the request timestamp. SDKs send
        # X-Amz-Date; a few use the Date header. Without either we can't
        # reproduce what was signed -- refuse rather than sign over an empty
        # timestamp.
        amz_date = ctx.header_get("x-amz-date") or ctx.header_get("date")
        if not amz_date:
            print(
                "[sigv4] request has no X-Amz-Date or Date header; cannot "
                "reproduce the timestamp the request was signed with. Leaving "
                "the request unsigned-as-is.",
                flush=True,
            )
            return False
        ctx.header_set("Authorization", sigv4_resign(
            method=ctx.method,
            path=ctx.path,
            host=ctx.host,
            header_get=ctx.header_get,
            body=ctx.body_bytes(),
            scope=scope,
            amz_date=amz_date,
            access_key_id=ctx.secret("access_key_id"),
            secret_access_key=ctx.secret("secret_access_key"),
        ))
        return True

    def on_response(self, ctx: ResponseCtx) -> bool:  # noqa: D401 - no-op seam
        return False


SCHEMES: dict[str, Scheme] = {
    s.name: s for s in (BearerScheme(), BasicScheme(), BodyScheme(),
                        SigV4Scheme())
}
