"""Tests for the SigV4 sign-family scheme (proxy/schemes.py).

The correctness anchor is AWS's own published worked example (GET iam
ListUsers): if our independent re-implementation reproduces AWS's signature,
the canonicalization, signing-key derivation, and StringToSign are all right.
https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
"""
import base64
from types import SimpleNamespace

from mitmproxy.test import tflow, tutils

import addon
import schemes
from config import Transform

# AWS published example credentials + expected result.
AKID = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AMZ_DATE = "20150830T123600Z"
EXPECTED_SIG = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
SCOPE_STR = "20150830/us-east-1/iam/aws4_request"


def test_parse_authorization():
    auth = (f"AWS4-HMAC-SHA256 Credential=DUMMY/{SCOPE_STR}, "
            "SignedHeaders=content-type;host;x-amz-date, Signature=deadbeef")
    scope = schemes._parse_sigv4_authorization(auth)
    assert scope == {
        "date": "20150830", "region": "us-east-1", "service": "iam",
        "signed_headers": ["content-type", "host", "x-amz-date"],
    }


def test_parse_authorization_rejects_non_sigv4():
    assert schemes._parse_sigv4_authorization("Bearer abc") is None


def test_resign_matches_aws_published_vector():
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "host": "iam.amazonaws.com",
        "x-amz-date": AMZ_DATE,
    }
    auth = schemes.sigv4_resign(
        method="GET",
        path="/?Action=ListUsers&Version=2010-05-08",
        host="iam.amazonaws.com",
        header_get=lambda n: headers.get(n.lower()),
        body=b"",
        scope={"date": "20150830", "region": "us-east-1", "service": "iam",
               "signed_headers": ["content-type", "host", "x-amz-date"]},
        amz_date=AMZ_DATE,
        access_key_id=AKID,
        secret_access_key=SECRET,
    )
    assert auth == (
        f"AWS4-HMAC-SHA256 Credential={AKID}/{SCOPE_STR}, "
        "SignedHeaders=content-type;host;x-amz-date, "
        f"Signature={EXPECTED_SIG}"
    )


def test_uri_encode_double_encodes_for_non_s3():
    # The wire path is encoded once; non-S3 canonical URI encodes it again.
    assert schemes._uri_encode("/a b", encode_slash=False) == "/a%20b"
    assert schemes._uri_encode("/a%20b", encode_slash=False) == "/a%2520b"


def test_uri_encode_bytes_roundtrips_raw_octets():
    """Byte-oriented encoding round-trips a non-UTF-8 octet exactly, instead of
    mangling it through a lossy UTF-8 decode (the V2#6 bug)."""
    from urllib.parse import unquote_to_bytes
    assert schemes._uri_encode_bytes(unquote_to_bytes("a%FFb")) == "a%FFb"
    # `+` is a literal plus (-> %2B); a space is %20 -- never confused.
    assert schemes._uri_encode_bytes(unquote_to_bytes("a+b")) == "a%2Bb"
    assert schemes._uri_encode_bytes(unquote_to_bytes("a%20b")) == "a%20b"


def test_query_canonicalization_distinguishes_raw_bytes():
    """A `%FF` query byte and the UTF-8 of U+FFFD (`%EF%BF%BD`) must canonicalize
    DIFFERENTLY -> different signatures. The old str-based unquote collapsed both
    to U+FFFD, so the two queries signed identically."""
    def _sign(qval):
        return schemes.sigv4_resign(
            method="GET", path=f"/?x={qval}", host="h.example.com",
            header_get=lambda n: {"host": "h.example.com",
                                  "x-amz-date": AMZ_DATE}.get(n.lower()),
            body=b"",
            scope={"date": "20150830", "region": "us-east-1", "service": "s3",
                   "signed_headers": ["host", "x-amz-date"]},
            amz_date=AMZ_DATE, access_key_id=AKID, secret_access_key=SECRET)
    assert _sign("%FF") != _sign("%EF%BF%BD")


# ---- the scheme via the addon (re-sign in place) ----

def _state(hosts):
    class Creds:
        def __init__(self, h): self._h = h
        def intercepts(self, sni): return bool(sni) and sni in self._h
        def intercept_hosts(self): return set(self._h)
        def transforms_for(self, host): return list(self._h.get(host, []))
        def inward_bindings(self): return []
        def rule_set(self):
            import rules
            return rules.RuleSet()
    return SimpleNamespace(creds=Creds(hosts))


def _sigv4_transform():
    return Transform("aws", schemes.SCHEMES["sigv4"], {}, None,
                     {"access_key_id": AKID, "secret_access_key": SECRET})


def test_addon_resigns_request_with_real_key():
    """An incoming placeholder-signed request is re-signed with the real key,
    reproducing the AWS vector signature and swapping in the real key id."""
    req = tutils.treq(host="iam.amazonaws.com", method=b"GET",
                      path=b"/?Action=ListUsers&Version=2010-05-08", content=b"")
    req.headers.clear()
    req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
    req.headers["host"] = "iam.amazonaws.com"
    req.headers["x-amz-date"] = AMZ_DATE
    req.headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential=THROWAWAY/{SCOPE_STR}, "
        "SignedHeaders=content-type;host;x-amz-date, Signature=00")
    flow = tflow.tflow(req=req)

    addon.HostnameLogger(_state({"iam.amazonaws.com": [_sigv4_transform()]})).request(flow)

    assert flow.request.headers["authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={AKID}/{SCOPE_STR}, "
        "SignedHeaders=content-type;host;x-amz-date, "
        f"Signature={EXPECTED_SIG}")


def test_addon_ignores_non_sigv4_request():
    """A request without a SigV4 Authorization is left untouched."""
    req = tutils.treq(host="iam.amazonaws.com", path=b"/")
    req.headers.clear()
    req.headers["authorization"] = "Bearer something"
    flow = tflow.tflow(req=req)
    addon.HostnameLogger(_state({"iam.amazonaws.com": [_sigv4_transform()]})).request(flow)
    assert flow.request.headers["authorization"] == "Bearer something"


def test_addon_refuses_resign_with_session_token():
    """Temporary (STS) creds carry X-Amz-Security-Token; the proxy can't pair a
    real long-term key with a throwaway session token, so it refuses to re-sign
    and leaves the request unmodified (rather than emitting a doomed signature)."""
    req = tutils.treq(host="iam.amazonaws.com", method=b"GET",
                      path=b"/?Action=ListUsers&Version=2010-05-08", content=b"")
    req.headers.clear()
    req.headers["host"] = "iam.amazonaws.com"
    req.headers["x-amz-date"] = AMZ_DATE
    req.headers["x-amz-security-token"] = "throwaway-session-token"
    orig = (f"AWS4-HMAC-SHA256 Credential=THROWAWAY/{SCOPE_STR}, "
            "SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=00")
    req.headers["authorization"] = orig
    flow = tflow.tflow(req=req)
    addon.HostnameLogger(_state({"iam.amazonaws.com": [_sigv4_transform()]})).request(flow)
    assert flow.request.headers["authorization"] == orig  # unchanged, not re-signed


def test_addon_refuses_resign_without_timestamp_header():
    """Without X-Amz-Date or Date, the proxy can't reproduce the signed
    timestamp, so it refuses rather than signing over an empty one."""
    req = tutils.treq(host="iam.amazonaws.com", method=b"GET", path=b"/", content=b"")
    req.headers.clear()
    req.headers["host"] = "iam.amazonaws.com"
    orig = (f"AWS4-HMAC-SHA256 Credential=THROWAWAY/{SCOPE_STR}, "
            "SignedHeaders=host, Signature=00")
    req.headers["authorization"] = orig
    flow = tflow.tflow(req=req)
    addon.HostnameLogger(_state({"iam.amazonaws.com": [_sigv4_transform()]})).request(flow)
    assert flow.request.headers["authorization"] == orig  # refused


def test_addon_resigns_using_date_header_fallback():
    """A request that carries only a Date header (no X-Amz-Date) is still
    re-signed, keyed to that timestamp."""
    req = tutils.treq(host="iam.amazonaws.com", method=b"GET", path=b"/", content=b"")
    req.headers.clear()
    req.headers["host"] = "iam.amazonaws.com"
    req.headers["date"] = AMZ_DATE
    orig = (f"AWS4-HMAC-SHA256 Credential=THROWAWAY/{SCOPE_STR}, "
            "SignedHeaders=host, Signature=00")
    req.headers["authorization"] = orig
    flow = tflow.tflow(req=req)
    addon.HostnameLogger(_state({"iam.amazonaws.com": [_sigv4_transform()]})).request(flow)
    auth = flow.request.headers["authorization"]
    assert auth != orig
    assert auth.startswith(f"AWS4-HMAC-SHA256 Credential={AKID}/{SCOPE_STR}")
