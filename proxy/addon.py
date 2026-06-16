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
        sni = data.client_hello.sni
        # The earliest, highest-blast-radius hook: it runs user-influenced glob
        # regexes (creds.intercepts). It must NEVER take the flow down -- an
        # unhandled error here would break ALL TLS. On any failure, fail SAFE to
        # passthrough (don't TLS-terminate a connection we couldn't classify).
        try:
            intercept = self._state.creds.intercepts(sni)
        except Exception as e:
            print(f"[sni] {sni or '<no-sni>'} intercept decision failed: {e}; "
                  f"passthrough", flush=True)
            data.ignore_connection = True
            return
        if intercept:
            print(f"[sni] {sni} (intercept)", flush=True)
            return
        print(f"[sni] {sni or '<no-sni>'} (passthrough)", flush=True)
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        creds = self._state.creds
        req = flow.request
        host = req.pretty_host
        applied: list[str] = []
        fired: list = []  # the request-time Transform objects whose on_request fired
        for t in creds.transforms_for(host):
            ctx = RequestCtx(req, t.secrets, t.params, t.placeholder)
            try:
                if t.scheme.on_request(ctx):
                    applied.append(t.scheme.name)
                    fired.append(t)
            except Exception as e:  # a scheme must never take the flow down
                print(f"[scheme] {t.scheme.name} on {host} failed: {e}", flush=True)

        # Record which bindings fired so the response hook runs on_response only
        # for them. A binding keys on its own placeholder, so only the one that
        # matched this request fires -- that's how re-seal bindings sharing a
        # token endpoint are disambiguated (the response carries no binding id).
        # We stash the request-time Transform OBJECTS, not just their names: the
        # response hook must re-seal against the exact binding that fired even if
        # POST /admin/config swaps state.creds while the token request is in
        # flight (otherwise a stale-name lookup could miss and let the real token
        # through). See response().
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
        # Re-seal seam: a re-seal scheme mints a token from this response and
        # registers a dynamic placeholder via the minter. Run on_response only
        # for the bindings whose on_request fired on THIS flow (the request-time
        # Transform objects recorded above). No fired binding -> nothing to do.
        fired = flow.metadata.get("credproxy_fired")
        if not fired:
            return
        # Mint into the LIVE creds (so later API-host requests see the dynamic
        # placeholder), but re-seal using the request-time transforms -- NOT a
        # fresh transforms_for() lookup -- so a config swap that landed between
        # the token request and this response can't drop the binding and let the
        # real token through.
        host = flow.request.pretty_host
        minter = RuntimeMinter(self._state.creds, placeholders.generate)
        for t in fired:
            # ResponseCtx wraps the whole flow: a re-seal scheme can read the
            # request it answered (host/path) AND read/mutate the response.
            ctx = ResponseCtx(flow, t.secrets, t.params, t.placeholder, minter=minter)
            try:
                t.scheme.on_response(ctx)
            except Exception as e:
                print(f"[scheme] {t.scheme.name} response on {host} failed: {e}",
                      flush=True)
                # FAIL CLOSED for the re-seal family: this binding's on_request
                # fired, so this is a token-endpoint response that MUST be
                # re-sealed. We couldn't, and the original body may still carry
                # the real minted token -- so withhold it from the workspace
                # rather than forward it. (Substitute/sign schemes don't mutate
                # the response, so a failure there leaks nothing and we forward.)
                if getattr(t.scheme, "mutates_response", False):
                    flow.response = http.Response.make(
                        502,
                        b"credproxy: re-seal failed; original response withheld\n",
                        {"Content-Type": "text/plain"},
                    )
                    return
