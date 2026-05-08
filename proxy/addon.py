"""Proxy mitmproxy addon: terminate configured hosts, substitute placeholders.

For SNIs in `creds.intercept_hosts()`, mitmproxy terminates TLS using its
CA; the `request` hook scans configured headers and substring-replaces
the configured placeholder with the real credential before forwarding.
For everything else, `ignore_connection = True` puts the flow into
byte-passthrough so we only see the SNI.

The substitution is intentionally string-level: the user's placeholder
can be a bare token, scheme-prefixed, or any other shape they want, and
the real value follows the same convention.

The sentinel-IP path is handled by bootstrap.py on a separate listener
(:39998), so this addon never sees those flows.
"""
from mitmproxy import http, tls

from config import Credentials


class HostnameLogger:
    def __init__(self, creds: Credentials):
        self._creds = creds

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        sni = data.client_hello.sni
        if sni in self._creds.intercept_hosts():
            print(f"[sni] {sni} (intercept)", flush=True)
            return
        print(f"[sni] {sni or '<no-sni>'} (passthrough)", flush=True)
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host
        substituted: list[str] = []
        for sub in self._creds.substitutions_for(host):
            value = req.headers.get(sub.header)
            if value is None or sub.placeholder not in value:
                continue
            req.headers[sub.header] = value.replace(sub.placeholder, sub.real)
            substituted.append(sub.header)

        if substituted:
            marker = f" (sub:{','.join(substituted)})"
        elif host in self._creds.intercept_hosts():
            marker = " (no-sub)"
        else:
            marker = ""
        print(f"[http] {req.method} {host}{req.path}{marker}", flush=True)
