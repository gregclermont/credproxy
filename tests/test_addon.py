"""Tests for proxy/addon.py — HostnameLogger intercept decision and substitution."""
from types import SimpleNamespace

from mitmproxy.test import tflow, tutils

import addon
from config import Substitution


class FakeCreds:
    """Hand-rolled Credentials for unit tests; bypasses YAML."""

    def __init__(self, hosts: dict[str, list[Substitution]]):
        self._hosts = hosts

    def intercept_hosts(self) -> set[str]:
        return set(self._hosts)

    def substitutions_for(self, host: str) -> list[Substitution]:
        return list(self._hosts.get(host, []))


def make_state(hosts):
    """HostnameLogger reads `state.creds` fresh on each call; tests mimic that
    by wrapping FakeCreds in a SimpleNamespace with a `.creds` attribute."""
    return SimpleNamespace(creds=FakeCreds(hosts))


def make_clienthello(sni):
    """Minimal mitmproxy.tls.ClientHelloData stand-in.

    The addon only reads .client_hello.sni and writes .ignore_connection,
    so a SimpleNamespace is enough.
    """
    return SimpleNamespace(
        client_hello=SimpleNamespace(sni=sni),
        ignore_connection=False,
    )


def make_flow(host="api.github.com", path="/user", headers=None):
    req = tutils.treq(host=host, path=path.encode())
    # tutils.treq sets a default header; clear it for predictable tests.
    req.headers.clear()
    for k, v in (headers or {}).items():
        req.headers[k] = v
    return tflow.tflow(req=req)


# ---- tls_clienthello: intercept decision ----

def test_clienthello_intercepted_does_not_set_ignore():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello("api.github.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is False


def test_clienthello_passthrough_sets_ignore():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello("example.com")
    log.tls_clienthello(data)
    assert data.ignore_connection is True


def test_clienthello_no_sni_passthrough():
    log = addon.HostnameLogger(make_state({"api.github.com": []}))
    data = make_clienthello(None)
    log.tls_clienthello(data)
    assert data.ignore_connection is True


# ---- request: substitution behavior ----

def test_request_substitutes_placeholder():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [Substitution("Authorization", "PH", "REAL")]
    }))
    flow = make_flow(headers={"Authorization": "Bearer PH"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer REAL"


def test_request_no_substitution_when_placeholder_absent_in_value():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [Substitution("Authorization", "PH", "REAL")]
    }))
    flow = make_flow(headers={"Authorization": "Bearer not_the_placeholder"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer not_the_placeholder"


def test_request_no_substitution_when_header_absent():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [Substitution("Authorization", "PH", "REAL")]
    }))
    flow = make_flow(headers={})
    log.request(flow)
    assert "Authorization" not in flow.request.headers


def test_request_multiple_headers_substituted():
    log = addon.HostnameLogger(make_state({
        "api.github.com": [
            Substitution("Authorization", "PH1", "REAL1"),
            Substitution("X-API-Key", "PH2", "REAL2"),
        ]
    }))
    flow = make_flow(headers={"Authorization": "PH1", "X-API-Key": "PH2"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "REAL1"
    assert flow.request.headers["X-API-Key"] == "REAL2"


def test_request_only_one_of_multiple_headers_present():
    """If only one configured header is present, only that one is substituted."""
    log = addon.HostnameLogger(make_state({
        "api.github.com": [
            Substitution("Authorization", "PH1", "REAL1"),
            Substitution("X-API-Key", "PH2", "REAL2"),
        ]
    }))
    flow = make_flow(headers={"Authorization": "PH1"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "REAL1"
    assert "X-API-Key" not in flow.request.headers


def test_request_placeholder_appears_twice_in_one_value():
    """str.replace replaces all occurrences."""
    log = addon.HostnameLogger(make_state({
        "api.github.com": [Substitution("X-Weird", "PH", "REAL")]
    }))
    flow = make_flow(headers={"X-Weird": "PH and PH again"})
    log.request(flow)
    assert flow.request.headers["X-Weird"] == "REAL and REAL again"


def test_request_non_intercepted_host_no_change():
    """request hook on a non-intercepted host (shouldn't fire in prod due
    to ignore_connection, but the addon must still no-op safely)."""
    log = addon.HostnameLogger(make_state({
        "api.github.com": [Substitution("Authorization", "PH", "REAL")]
    }))
    flow = make_flow(host="example.com", headers={"Authorization": "Bearer PH"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer PH"


def test_state_creds_swap_takes_effect_on_next_call():
    """In-process reload: mutating state.creds is visible to the next request."""
    state = make_state({"api.github.com": [Substitution("Authorization", "OLD", "OLDREAL")]})
    log = addon.HostnameLogger(state)
    flow = make_flow(headers={"Authorization": "OLD"})
    log.request(flow)
    assert flow.request.headers["Authorization"] == "OLDREAL"

    state.creds = FakeCreds({"api.github.com": [Substitution("Authorization", "NEW", "NEWREAL")]})
    flow2 = make_flow(headers={"Authorization": "NEW"})
    log.request(flow2)
    assert flow2.request.headers["Authorization"] == "NEWREAL"
