"""v0 addon: log hostnames, passthrough everything.

No TLS termination, no credential injection, no bootstrap endpoint
synthesis. Goal is to confirm the netns + iptables + mitmproxy
plumbing works and to start seeing what egresses from the sandbox.
"""
from mitmproxy import http, tls


class HostnameLogger:
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        sni = data.client_hello.sni or "<no-sni>"
        print(f"[sni] {sni}", flush=True)
        # v0: never terminate TLS. Forward bytes blindly to original dest.
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        # Only fires for plaintext HTTP (TLS is passthrough above).
        req = flow.request
        print(f"[http] {req.method} {req.pretty_host}{req.path}", flush=True)
