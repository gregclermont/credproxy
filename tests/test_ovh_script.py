"""Tests for the bundled OVH API scripted injector (ovh.star).

Builds a ScriptedScheme directly from the bundled source and drives
on_request against a RequestCtx, then independently recomputes the
expected SHA1 in Python to verify all four injected headers.
"""
import hashlib
from pathlib import Path

import pytest
from mitmproxy.test import tutils

import schemes
from starlark_runtime import ScriptedScheme

OVH = (Path(__file__).resolve().parents[1]
       / "cli" / "credproxy_cli" / "bundled" / "scripts" / "ovh.star").read_text()

_SLOTS = ("app_key", "app_secret", "consumer_key")


def _scheme():
    return ScriptedScheme("ovh", OVH, family="sign",
                          slots=_SLOTS, location_kind="header")


def _secrets():
    return {"app_key": "AK", "app_secret": "AS", "consumer_key": "CK"}


def test_ovh_sets_signed_headers():
    s = _scheme()
    req = tutils.treq(host="eu.api.ovh.com", method=b"GET", path=b"/1.0/me", content=b"")
    req.headers.clear()
    req.headers["host"] = "eu.api.ovh.com"
    ctx = schemes.RequestCtx(req, _secrets(), {}, None)

    assert s.on_request(ctx) is True

    ts = req.headers["X-Ovh-Timestamp"]
    # Empty body -> base has "++" between url and ts
    base = "AS+CK+GET+https://eu.api.ovh.com/1.0/me++" + ts
    expected_sig = "$1$" + hashlib.sha1(base.encode()).hexdigest()

    assert req.headers["X-Ovh-Signature"] == expected_sig
    assert req.headers["X-Ovh-Application"] == "AK"
    assert req.headers["X-Ovh-Consumer"] == "CK"


def test_ovh_signs_hostname_not_ip():
    """Regression for #7: in transparent mode flow.request.host is the
    destination IP; the script must sign the HOSTNAME URL (from pretty_host /
    the Host header), or OVH rejects with 'Invalid signature'."""
    s = _scheme()
    req = tutils.treq(host="54.88.241.89", method=b"GET", path=b"/1.0/me", content=b"")
    req.headers.clear()
    req.headers["host"] = "eu.api.ovh.com"   # the real hostname
    ctx = schemes.RequestCtx(req, _secrets(), {}, None)

    assert s.on_request(ctx) is True

    ts = req.headers["X-Ovh-Timestamp"]
    # Signed over the hostname URL, not https://54.88.241.89/...
    base = "AS+CK+GET+https://eu.api.ovh.com/1.0/me++" + ts
    expected_sig = "$1$" + hashlib.sha1(base.encode()).hexdigest()
    assert req.headers["X-Ovh-Signature"] == expected_sig


def test_ovh_placeholder_present_signs_and_overwrites_app():
    """With a placeholder, the workspace presents it as X-Ovh-Application; the
    proxy signs and overwrites the four headers with the real app key."""
    s = _scheme()
    req = tutils.treq(host="eu.api.ovh.com", method=b"GET", path=b"/1.0/me", content=b"")
    req.headers.clear()
    req.headers["host"] = "eu.api.ovh.com"
    req.headers["X-Ovh-Application"] = "PLACEHOLDER-APP"
    ctx = schemes.RequestCtx(req, _secrets(), {}, "PLACEHOLDER-APP")

    assert s.on_request(ctx) is True
    assert req.headers["X-Ovh-Application"] == "AK"   # placeholder -> real app key
    assert "X-Ovh-Signature" in req.headers


def test_ovh_placeholder_mismatch_skips():
    """No / wrong X-Ovh-Application -> not our request; add no signature."""
    s = _scheme()
    req = tutils.treq(host="eu.api.ovh.com", method=b"GET", path=b"/1.0/me", content=b"")
    req.headers.clear()
    req.headers["host"] = "eu.api.ovh.com"   # no X-Ovh-Application presented
    ctx = schemes.RequestCtx(req, _secrets(), {}, "PLACEHOLDER-APP")

    assert s.on_request(ctx) is False
    assert "X-Ovh-Signature" not in req.headers


def test_ovh_post_with_body():
    s = _scheme()
    body = '{"description":"test"}'
    req = tutils.treq(
        host="eu.api.ovh.com",
        method=b"POST",
        path=b"/1.0/domain/zone/example.com/record",
        content=body.encode(),
    )
    req.headers.clear()
    req.headers["host"] = "eu.api.ovh.com"
    req.headers["Content-Type"] = "application/json"
    ctx = schemes.RequestCtx(req, _secrets(), {}, None)

    assert s.on_request(ctx) is True

    ts = req.headers["X-Ovh-Timestamp"]
    url = "https://eu.api.ovh.com/1.0/domain/zone/example.com/record"
    base = "AS+CK+POST+" + url + "+" + body + "+" + ts
    expected_sig = "$1$" + hashlib.sha1(base.encode()).hexdigest()

    assert req.headers["X-Ovh-Signature"] == expected_sig
    assert req.headers["X-Ovh-Application"] == "AK"
    assert req.headers["X-Ovh-Consumer"] == "CK"
