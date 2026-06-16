"""Proxy mitmproxy addon: terminate configured hosts, run injection schemes.

For SNIs that `state.creds.intercepts(sni)` accepts (an exact binding host, a
glob pattern like `*.amazonaws.com`, or a live re-seal host), mitmproxy
terminates TLS using its CA; the `request` hook runs each binding's scheme
(`on_request`) to inject the credential before forwarding. For everything else,
`ignore_connection = True` puts the flow into byte-passthrough so we only see
the SNI.

The `response` hook runs each transform's `on_response` (a no-op for the
substitute family today; the seam the re-seal schemes will use to mint and
register dynamic placeholders).

The addon reads `state.creds` fresh on every call (rather than caching it at
construction) so an in-process config reload -- admin_config swapping
`state.creds` under the same AppState -- takes effect immediately for new
flows without a process restart.

The sentinel-IP path is handled by the merged HTTP listener (admin +
bootstrap) on a separate port, so this addon never sees those flows.
"""
from mitmproxy import http, tls

import placeholders
from config import RuntimeMinter
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
        if creds.intercepts(sni):
            print(f"[sni] {sni} (intercept)", flush=True)
            return
        print(f"[sni] {sni or '<no-sni>'} (passthrough)", flush=True)
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        creds = self._state.creds
        req = flow.request
        host = req.pretty_host
        applied: list[str] = []
        fired: list[str] = []
        for t in creds.transforms_for(host):
            ctx = RequestCtx(req, t.secrets, t.params, t.placeholder)
            try:
                if t.scheme.on_request(ctx):
                    applied.append(t.scheme.name)
                    fired.append(t.name)
            except Exception as e:  # a scheme must never take the flow down
                print(f"[scheme] {t.scheme.name} on {host} failed: {e}", flush=True)

        # Record which bindings fired so the response hook runs on_response only
        # for them. A binding keys on its own placeholder, so only the one that
        # matched this request fires -- that's how re-seal bindings sharing a
        # token endpoint are disambiguated (the response carries no binding id).
        if fired:
            flow.metadata["credproxy_fired"] = fired

        if applied:
            marker = f" (inject:{','.join(applied)})"
        elif creds.intercepts(host):
            marker = " (no-inject)"
        else:
            marker = ""
        # Log the path WITHOUT the query string: query params routinely carry
        # secrets (OAuth `?code=`, presigned-URL signatures, API keys), and this
        # line goes to the proxy's stdout -> `docker logs`.
        path = req.path.split("?", 1)[0]
        print(f"[http] {req.method} {host}{path}{marker}", flush=True)

    def response(self, flow: http.HTTPFlow) -> None:
        # Re-seal seam: plumbed from day one, no-op until a scheme
        # uses on_response. Iterate the same transforms so a future re-seal
        # scheme can mint a token from the response and register a dynamic
        # placeholder via creds.register_runtime(...).
        # Only run on_response for bindings whose on_request fired on THIS flow
        # (recorded in the request hook). No fired binding -> nothing to do.
        fired = flow.metadata.get("credproxy_fired")
        if not fired:
            return
        fired_set = set(fired)
        creds = self._state.creds
        host = flow.request.pretty_host
        # The minter lets a re-seal scheme register a dynamic placeholder
        # (placeholder -> minted token, TTL) on the API hosts via creds.
        minter = RuntimeMinter(creds, placeholders.generate)
        for t in creds.transforms_for(host):
            if t.name not in fired_set:
                continue
            # ResponseCtx wraps the whole flow: a re-seal scheme can read the
            # request it answered (host/path) AND read/mutate the response.
            ctx = ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
            try:
                t.scheme.on_response(ctx)
            except Exception as e:
                print(f"[scheme] {t.scheme.name} response on {host} failed: {e}",
                      flush=True)
