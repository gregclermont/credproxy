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
import json
from dataclasses import dataclass, field

from mitmproxy import http, tls

import audit
import log
import placeholders
import rules
from config import RuntimeMinter
from schemes import RequestCtx, ResponseCtx


@dataclass
class _RulePhaseResult:
    """Outcome of running one phase's matched rules through the shared evaluator.
    `flow.response` and the audit stream are already handled by the evaluator;
    the caller only does phase-specific `[http]` plumbing from these fields."""
    terminated: bool                       # a terminal rule OR a fail-closed 502 fired
    rewrite_marks: list = field(default_factory=list)  # non-terminal markers, in order
    terminal_mark: str | None = None       # "block:NAME" | "respond:NAME" | "rule-error:NAME"


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
            log.emit("sni", sni=sni, decision="passthrough", error=str(e))
            data.ignore_connection = True
            return
        if intercept:
            log.emit("sni", sni=sni, decision="intercept")
            return
        log.emit("sni", sni=sni, decision="passthrough")
        data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        creds = self._state.creds
        req = flow.request
        host = req.pretty_host
        # Log the path WITHOUT the query string: query params routinely carry
        # secrets (OAuth `?code=`, presigned-URL signatures, API keys), and this
        # line goes to the proxy's stdout -> `docker logs`. Also the path we
        # match rules against.
        path = req.path.split("?", 1)[0]

        # --- rules run BEFORE injection (the security invariant) --------------
        # A blocked request never receives a credential and never logs as
        # credential use; a request rewrite happens before sigv4 signs. A
        # terminal rule (block/respond, or a script that calls block/respond)
        # short-circuits: the synthetic response is set here and we return.
        rule_markers, terminated = self._apply_request_rules(
            flow, creds, host, req.method, path)
        if terminated:
            # A terminal request rule (block/respond, or the fail-closed 502)
            # decided this flow and set flow.response. mitmproxy still fires
            # response() for that synthetic response, so mark the flow: a
            # terminated request has no upstream to govern, and a later response
            # rule must NEVER undo the terminal decision (first-terminal-wins).
            # Both terminal exits of _apply_request_rules set flow.response, so
            # this single check covers the clean block/respond path AND the 502.
            flow.metadata["credproxy_rule_terminated"] = True
            return

        applied: list[str] = []
        fired: list = []  # the request-time Transform objects whose on_request fired
        candidates = creds.transforms_for(host)
        for t in candidates:
            ctx = RequestCtx(req, t.secrets, t.params, t.placeholder)
            try:
                if t.scheme.on_request(ctx):
                    applied.append(t.scheme.name)
                    fired.append(t)
            except Exception as e:  # a scheme must never take the flow down
                log.emit("scheme", scheme=t.scheme.name, host=host,
                         phase="request", error=str(e))

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

        marks = list(rule_markers)
        if applied:
            marks.append(f"inject:{','.join(applied)}")
        elif candidates:
            # `candidates` (bindings evaluated for this host), NOT
            # creds.intercepts(host): a rule-only host is intercepted but has no
            # binding to decline, so `(no-inject)` would falsely imply one was
            # evaluated -- and the audit below keys on `candidates` too, so the
            # marker and the event must agree.
            marks.append("no-inject")
        log.emit("http", method=req.method, host=host, path=path,
                 marks=marks or None)

        # Durable audit stream (#24): one event per fired binding, plus a single
        # no-inject event when an intercepted host had candidate bindings but
        # none fired. Names/host/method/path only -- never a secret or a header
        # value. The addon marks bindings that fired via `fired`; emit from that.
        for t in fired:
            audit.emit("inject", binding=t.name, scheme=t.scheme.name,
                       host=host, method=req.method, path=path,
                       outcome="injected")
        if candidates and not applied:  # candidate bindings existed, none fired
            audit.emit("no-inject", host=host, method=req.method, path=path,
                       outcome="declined")

    # ---- rule evaluation ----------------------------------------------------

    def _evaluate_rules(self, flow, matched, rctx, apply_fn, *, host, method,
                        path) -> _RulePhaseResult:
        """The ONE home of the rule-evaluation security invariants, shared by both
        phases: strict declaration order, first-terminal-wins, fail-closed, and
        the durable audit event per rule. Mutates `flow` (rewrites via `rctx`; sets
        `flow.response` on a terminal rule or a fail-closed 502) and emits audit;
        returns the outcome so the caller can do phase-specific `[http]` logging.
        `apply_fn` is `rules.apply_request_rule` / `apply_response_rule`; `rctx` the
        matching RuleRequestCtx / RuleResponseCtx."""
        marks: list[str] = []
        for rule in matched:
            try:
                terminal = apply_fn(rule, rctx)
                # Build the synthetic response INSIDE the guard: a malformed script
                # `respond(...)` (non-string body, bad header) makes _synthesize
                # raise, and mitmproxy would SWALLOW an escaping addon exception and
                # forward upstream un-governed. Fail closed.
                synthetic = self._synthesize(rule, rctx.pending) if terminal else None
            except Exception as e:  # RuleError or a synthesis failure -> fail closed
                # Rule scripts hold no secret, so the full cause is safe to log --
                # and `error` is a JSON VALUE here, so a workspace-influenced
                # message (a script `fail(req_body())`) can't spill a forged
                # `credproxy {...}` record onto its own line (see log.py).
                log.emit("rule-error", rule=rule.name, host=host, method=method,
                         path=path, error=str(e))
                audit.emit("rule", rule=rule.name, action=rule.action, host=host,
                           method=method, path=path, outcome="error",
                           visible=rule.visible)
                flow.response = http.Response.make(
                    502, f"credproxy: rule '{rule.name}' failed\n".encode(),
                    {"Content-Type": "text/plain"})
                return _RulePhaseResult(True, marks, f"rule-error:{rule.name}")
            if terminal:
                audit.emit("rule", rule=rule.name, action=rule.action, host=host,
                           method=method, path=path, outcome=rctx.pending.kind,
                           visible=rule.visible)
                flow.response = synthetic
                return _RulePhaseResult(True, marks,
                                        f"{rctx.pending.kind}:{rule.name}")
            # Non-terminal: a declarative rewrite or a script that only mutated.
            audit.emit("rule", rule=rule.name, action=rule.action, host=host,
                       method=method, path=path, outcome="rewrite",
                       visible=rule.visible)
            marks.append(f"rewrite:{rule.name}")
        return _RulePhaseResult(False, marks, None)

    def _apply_request_rules(self, flow, creds, host, method, path):
        """Request-phase rules, BEFORE injection. Returns `(markers, terminated)`:
        on a non-terminal outcome the rewrite `markers` are handed back for the
        caller to fold into the injection `[http]` line; on a terminal outcome
        (block/respond, or a fail-closed 502) this logs its own `[http]` line and
        signals the caller to skip injection."""
        # Rules match against the PRE-rewrite host/path (captured before any
        # rewrite runs). Correct today (a rewrite can't touch the request line --
        # only headers, and Host rewrites are rejected); if a path-rewrite action
        # is added, decide matching semantics explicitly rather than letting a
        # rewrite silently re-target later rules.
        rule_set = creds.rule_set()
        matched = rule_set.request_rules(method, host, path) if rule_set else []
        if not matched:
            return [], False
        r = self._evaluate_rules(flow, matched, rules.RuleRequestCtx(flow.request),
                                 rules.apply_request_rule,
                                 host=host, method=method, path=path)
        if r.terminated:
            log.emit("http", method=method, host=host, path=path,
                     marks=r.rewrite_marks + [r.terminal_mark])
            return [], True                     # already logged; nothing to fold
        return r.rewrite_marks, False           # fold into the injection line

    def _apply_response_rules(self, flow, creds, host) -> None:
        """Response-phase rules, AFTER re-seal (a token-endpoint response is
        already sealed into a placeholder before any rule sees it). Emits its own
        folded `[http]` line for whatever ran."""
        # A terminal request rule already decided this flow (block/respond/502):
        # the response is synthetic policy output with no upstream to govern, and
        # a response rule must NOT run -- else a later on_response script could
        # turn a blocked request into a success, or a resp_remove_headers rule
        # could strip X-Credproxy-Rule off a visible block. First-terminal-wins.
        if flow.metadata.get("credproxy_rule_terminated"):
            return
        rule_set = creds.rule_set()
        if not rule_set:
            return
        req = flow.request
        path = req.path.split("?", 1)[0]
        matched = rule_set.response_rules(req.method, host, path)
        if not matched:
            return
        r = self._evaluate_rules(flow, matched, rules.RuleResponseCtx(flow),
                                 rules.apply_response_rule,
                                 host=host, method=req.method, path=path)
        marks = r.rewrite_marks + ([r.terminal_mark] if r.terminated else [])
        if marks:
            log.emit("http", method=req.method, host=host, path=path, marks=marks)

    def _synthesize(self, rule, pending: "rules.SyntheticResponse") -> http.Response:
        """Build the synthetic mitmproxy response for a terminal rule, applying
        the visibility policy. A VISIBLE terminal rule self-identifies (an
        `X-Credproxy-Rule` header; a `block` also gets a `{"credproxy":...}` JSON
        body). A HIDDEN `block` is a bare status with no body and no marker; a
        HIDDEN `respond` is the author's exact counterfeit, unmarked."""
        # Validate the (possibly script-supplied) pending response so a bad type
        # raises HERE, inside the caller's fail-closed guard, rather than escaping
        # as an addon-hook exception mitmproxy would swallow (forwarding upstream).
        if not isinstance(pending.status, int) or isinstance(pending.status, bool) \
                or not (100 <= pending.status <= 599):
            raise ValueError(f"synthetic status must be an int 100-599, "
                             f"got {pending.status!r}")
        if not isinstance(pending.body, (str, bytes)):
            raise ValueError(f"synthetic body must be str/bytes, "
                             f"got {type(pending.body).__name__}")
        headers = {}
        for k, v in dict(pending.headers).items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("synthetic headers must be string -> string")
            headers[k] = v
        body = pending.body
        # Attribution is OURS to set: strip any X-Credproxy-Rule the author's
        # respond(...) headers supplied (case-insensitive) BEFORE the visible/
        # hidden split, so a hidden rule can't self-identify and a visible rule
        # can't emit two contradictory attribution lines (author's + ours).
        for k in [k for k in headers if k.lower() == "x-credproxy-rule"]:
            del headers[k]
        if pending.kind == "block":
            if rule.visible:
                headers.setdefault("Content-Type", "application/json")
                headers["X-Credproxy-Rule"] = rule.name
                body = json.dumps({"credproxy": {"blocked_by": rule.name}}) + "\n"
            else:
                body = ""  # bare status, no body, no attribution
        else:  # respond -- author-supplied body kept verbatim
            if rule.visible:
                headers["X-Credproxy-Rule"] = rule.name
        return http.Response.make(
            pending.status,
            body.encode("utf-8") if isinstance(body, str) else body,
            headers,
        )

    def response(self, flow: http.HTTPFlow) -> None:
        creds = self._state.creds
        host = flow.request.pretty_host

        # Re-seal seam: a re-seal scheme mints a token from this response and
        # registers a dynamic placeholder via the minter. Run on_response only
        # for the bindings whose on_request fired on THIS flow (the request-time
        # Transform objects recorded above). No fired binding -> skip to rules.
        fired = flow.metadata.get("credproxy_fired")
        if fired:
            # Mint into the LIVE creds (so later API-host requests see the dynamic
            # placeholder), but re-seal using the request-time transforms -- NOT a
            # fresh transforms_for() lookup -- so a config swap that landed between
            # the token request and this response can't drop the binding and let
            # the real token through.
            for t in fired:
                # Per-binding minter so the runtime transform it registers is
                # named `reseal:<this binding>` -- the later injection audit (when
                # the minted placeholder is used on an API host) then correlates
                # with this binding's `reseal` mint event below.
                minter = RuntimeMinter(creds, placeholders.generate,
                                       source_binding=t.name, source_host=host,
                                       source_scheme=t.scheme.name)
                # ResponseCtx wraps the whole flow: a re-seal scheme can read the
                # request it answered (host/path) AND read/mutate the response.
                ctx = ResponseCtx(flow, t.secrets, t.params, t.placeholder,
                                  minter=minter)
                try:
                    # The mint audit is emitted by RuntimeMinter.mint() itself (so
                    # a script that mints without returning True still audits), so
                    # the return value is ignored here.
                    t.scheme.on_response(ctx)
                except Exception as e:
                    log.emit("scheme", scheme=t.scheme.name, host=host,
                             phase="response", error=str(e))
                    # FAIL CLOSED for the re-seal family: this binding's on_request
                    # fired, so this is a token-endpoint response that MUST be
                    # re-sealed. We couldn't, and the original body may still carry
                    # the real minted token -- so withhold it rather than forward.
                    # (Substitute/sign schemes don't mutate the response, so a
                    # failure there leaks nothing and we forward.)
                    if getattr(t.scheme, "mutates_response", False):
                        flow.response = http.Response.make(
                            502,
                            b"credproxy: re-seal failed; original response withheld\n",
                            {"Content-Type": "text/plain"},
                        )
                        return

        # Response rules run AFTER re-seal (the security invariant).
        self._apply_response_rules(flow, creds, host)
