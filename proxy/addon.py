"""Proxy mitmproxy addon: terminate configured hosts, run injection schemes.

For SNIs in `state.creds.intercept_hosts()`, mitmproxy terminates TLS using
its CA; the `request` hook runs each binding's scheme (`on_request`) to inject
the credential before forwarding. For everything else, `ignore_connection =
True` puts the flow into byte-passthrough so we only see the SNI.

The `response` hook runs each transform's `on_response` (a no-op for the
substitute family today; the seam the re-seal schemes will use to mint and
register dynamic placeholders -- design-v3).

The addon reads `state.creds` fresh on every call (rather than caching it at
construction) so an in-process config reload -- admin_config swapping
`state.creds` under the same AppState -- takes effect immediately for new
flows without a process restart.

The sentinel-IP path is handled by the merged HTTP listener (admin +
bootstrap) on a separate port, so this addon never sees those flows.
"""
from mitmproxy import http, tls

from schemes import RequestCtx, ResponseCtx


class HostnameLogger:
    def __init__(self, state):
        # `state` is duck-typed: anything with a `.creds` attribute
        # pointing to a config.Credentials. In production, an
        # admin.AppState; in tests, a SimpleNamespace.
        self._state = state

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        creds = self._state.creds
        sni = data.client_hello.sni
        if sni in creds.intercept_hosts():
            print(f"[sni] {sni} (intercept)", flush=True)
            return
        print(f"[sni] {sni or '<no-sni>'} (passthrough)", flush=True)
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        creds = self._state.creds
        req = flow.request
        host = req.pretty_host
        applied: list[str] = []
        for t in creds.transforms_for(host):
            ctx = RequestCtx(req, t.secrets, t.params, t.placeholder)
            try:
                if t.scheme.on_request(ctx):
                    applied.append(t.scheme)
            except Exception as e:  # a scheme must never take the flow down
                print(f"[scheme] {t.scheme.name} on {host} failed: {e}", flush=True)

        if applied:
            marker = f" (inject:{','.join(s.name for s in applied)})"
        elif host in creds.intercept_hosts():
            marker = " (no-inject)"
        else:
            marker = ""
        print(f"[http] {req.method} {host}{req.path}{marker}", flush=True)

    def response(self, flow: http.HTTPFlow) -> None:
        # Re-seal seam (design-v3): plumbed from day one, no-op until a scheme
        # uses on_response. Iterate the same transforms so a future re-seal
        # scheme can mint a token from the response and register a dynamic
        # placeholder via creds.register_runtime(...).
        creds = self._state.creds
        host = flow.request.pretty_host
        for t in creds.transforms_for(host):
            # ResponseCtx wraps the whole flow: a re-seal scheme can read the
            # request it answered (host/path) AND read/mutate the response.
            ctx = ResponseCtx(flow, t.secrets, t.params, t.placeholder)
            try:
                t.scheme.on_response(ctx)
            except Exception as e:
                print(f"[scheme] {t.scheme.name} response on {host} failed: {e}",
                      flush=True)
