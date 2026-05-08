"""Proxy mitmproxy addon: log SNI + HTTP Host, passthrough everything.

The sentinel-IP path is handled by bootstrap.py on a separate listener
(:39998), so this addon never sees those flows. v0 doesn't terminate any
TLS — `ignore_connection = True` puts the flow into byte-passthrough.
"""
from mitmproxy import http, tls


class HostnameLogger:
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        sni = data.client_hello.sni or "<no-sni>"
        print(f"[sni] {sni}", flush=True)
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        print(f"[http] {req.method} {req.pretty_host}{req.path}", flush=True)
