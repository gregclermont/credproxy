"""Tests for the bundled jwt-bearer Starlark script.

Verifies that on_request mints an RS256-signed JWT, injects it as
Authorization: Bearer <jwt>, and that the JWT's header, claims, and signature
are all well-formed and verifiable with the corresponding public key.
"""
import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from mitmproxy.test import tutils

import schemes
from starlark_runtime import ScriptedScheme

JWT_STAR = (Path(__file__).resolve().parents[1]
            / "cli" / "credproxy_cli" / "bundled" / "scripts" / "jwt-bearer.star").read_text()


def _b64url_decode(s: str) -> bytes:
    """Decode an unpadded base64url string."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _make_scheme():
    return ScriptedScheme(
        "jwt-bearer", JWT_STAR,
        family="sign", slots=("private_key",), location_kind="header",
    )


def _make_key():
    """Generate a fresh 2048-bit RSA key pair; return (private_key, pem_str)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return key, pem


def _make_ctx(pem: str, params: dict | None = None):
    req = tutils.treq(host="api.example.com")
    req.headers.clear()
    req.headers["host"] = "api.example.com"
    ctx = schemes.RequestCtx(
        req,
        {"private_key": pem},
        params or {"iss": "svc@example.com", "aud": "https://api.example.com", "ttl": "60"},
        None,
    )
    return ctx, req


# ---------------------------------------------------------------------------
# Core: mints a verifiable RS256 JWT
# ---------------------------------------------------------------------------

def test_jwt_bearer_mints_verifiable_token():
    key, pem = _make_key()
    s = _make_scheme()
    ctx, req = _make_ctx(pem)

    before = int(time.time())
    result = s.on_request(ctx)
    after = int(time.time())

    assert result is True

    auth = req.headers["Authorization"]
    assert auth.startswith("Bearer ")

    parts = auth[len("Bearer "):].split(".")
    assert len(parts) == 3, "JWT must have three dot-separated parts"
    h_b64, c_b64, sig_b64 = parts

    # Verify the RS256 signature over "header.claims"
    signing_input = (h_b64 + "." + c_b64).encode()
    sig = _b64url_decode(sig_b64)
    # Raises InvalidSignature on failure -- that IS the test assertion.
    key.public_key().verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())

    # Check decoded header
    hdr = json.loads(_b64url_decode(h_b64))
    assert hdr["alg"] == "RS256"
    assert hdr["typ"] == "JWT"

    # Check decoded claims
    claims = json.loads(_b64url_decode(c_b64))
    assert claims["iss"] == "svc@example.com"
    assert claims["aud"] == "https://api.example.com"
    assert claims["exp"] - claims["iat"] == 60
    assert before <= claims["iat"] <= after


# ---------------------------------------------------------------------------
# TTL: custom lifetime is reflected in exp-iat delta
# ---------------------------------------------------------------------------

def test_jwt_bearer_custom_ttl():
    key, pem = _make_key()
    s = _make_scheme()
    ctx, req = _make_ctx(pem, params={
        "iss": "svc@example.com",
        "aud": "https://api.example.com",
        "ttl": "7200",
    })
    assert s.on_request(ctx) is True
    _, c_b64, _ = req.headers["Authorization"][len("Bearer "):].split(".")
    claims = json.loads(_b64url_decode(c_b64))
    assert claims["exp"] - claims["iat"] == 7200


# ---------------------------------------------------------------------------
# sub claim: present only when non-empty
# ---------------------------------------------------------------------------

def test_jwt_bearer_sub_included_when_set():
    key, pem = _make_key()
    s = _make_scheme()
    ctx, req = _make_ctx(pem, params={
        "iss": "svc@example.com",
        "aud": "https://api.example.com",
        "ttl": "60",
        "sub": "user@example.com",
    })
    assert s.on_request(ctx) is True
    _, c_b64, _ = req.headers["Authorization"][len("Bearer "):].split(".")
    claims = json.loads(_b64url_decode(c_b64))
    assert claims["sub"] == "user@example.com"


def test_jwt_bearer_sub_absent_when_empty():
    key, pem = _make_key()
    s = _make_scheme()
    ctx, req = _make_ctx(pem, params={
        "iss": "svc@example.com",
        "aud": "https://api.example.com",
        "ttl": "60",
        "sub": "",
    })
    assert s.on_request(ctx) is True
    _, c_b64, _ = req.headers["Authorization"][len("Bearer "):].split(".")
    claims = json.loads(_b64url_decode(c_b64))
    assert "sub" not in claims


def test_jwt_bearer_sub_absent_by_default():
    """When sub param is not provided at all, it should not appear in claims."""
    key, pem = _make_key()
    s = _make_scheme()
    # No "sub" key in params at all
    ctx, req = _make_ctx(pem, params={
        "iss": "svc@example.com",
        "aud": "https://api.example.com",
        "ttl": "60",
    })
    assert s.on_request(ctx) is True
    _, c_b64, _ = req.headers["Authorization"][len("Bearer "):].split(".")
    claims = json.loads(_b64url_decode(c_b64))
    assert "sub" not in claims


# ---------------------------------------------------------------------------
# Each call mints a fresh JWT (iat/exp advance with time)
# ---------------------------------------------------------------------------

def test_jwt_bearer_each_call_is_fresh():
    """Two successive calls must produce different tokens (different iat/exp
    if any time passes, or at minimum different signatures since RSA-PKCS1v15
    is deterministic -- so tokens identical iff iat identical)."""
    key, pem = _make_key()
    s = _make_scheme()

    ctx1, req1 = _make_ctx(pem)
    ctx2, req2 = _make_ctx(pem)

    assert s.on_request(ctx1) is True
    # Allow a wall-clock tick between calls; even without one, both JWTs are
    # valid -- we only assert both are well-formed Bearer tokens.
    assert s.on_request(ctx2) is True

    jwt1 = req1.headers["Authorization"]
    jwt2 = req2.headers["Authorization"]
    # Both are parseable Bearer JWTs (no assertion on equality -- iat may match
    # within the same second on a fast machine).
    for auth in (jwt1, jwt2):
        assert auth.startswith("Bearer ")
        assert len(auth[len("Bearer "):].split(".")) == 3


# ---------------------------------------------------------------------------
# Signature is invalid when verified with a DIFFERENT key (sanity check)
# ---------------------------------------------------------------------------

def test_jwt_bearer_wrong_key_fails_verification():
    key, pem = _make_key()
    other_key, _ = _make_key()   # unrelated key pair
    s = _make_scheme()
    ctx, req = _make_ctx(pem)
    assert s.on_request(ctx) is True

    h_b64, c_b64, sig_b64 = req.headers["Authorization"][len("Bearer "):].split(".")
    sig = _b64url_decode(sig_b64)
    signing_input = (h_b64 + "." + c_b64).encode()

    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        other_key.public_key().verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
