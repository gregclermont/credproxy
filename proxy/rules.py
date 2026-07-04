"""Rules: a credential-free traffic-governance layer for intercepted hosts.

A *rule* is the sibling of a binding. Where a binding shapes a credential INTO a
request, a rule GOVERNS a request/response on an intercepted host: block it,
answer it with a stub, rewrite headers, or hand the flow to a sandboxed Starlark
script. Rules hold no secret, no provider, no placeholder.

Pipeline ordering is the security invariant (see addon.py), not a preference:

    request:   rules (declaration order) -> injection schemes -> upstream
    response:  scheme on_response (re-seal) -> response rules (declaration order)

Request rules run BEFORE injection, so a blocked request never receives a
credential and a rewrite happens before sigv4 signs. Response rules run AFTER
re-seal, so a token-endpoint response is already sealed into a placeholder before
any user rule sees it. Consequence: rule code -- declarative or script -- never
observes a real credential. It sees inert placeholders on the request side and
exactly what the workspace would see on the response side.

Matching is hostname + optional method + optional path glob. Host globs reuse
`hostmatch` verbatim (dot-spanning `*`, host-only). Path globs are fnmatch-
conventional and SEGMENT-aware: `*` matches within one path segment, `**` crosses
segments (`/repos/**` covers `/repos/a/b`). The `core/pathmatch.py` CLI mirror is
kept byte-parity with `path_to_regex` here (wire-parity tested).

Evaluation is strict declaration order: `rewrite` actions apply cumulatively; the
first terminal action (`block`/`respond`, or a `script` that calls `block`/
`respond`) short-circuits. A rule set carries its own host set so the intercept
decision is a UNION of binding hosts and rule hosts -- a host with only rules is
still TLS-terminated (see config.load_resolved).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from schemes import RequestCtx, ResponseCtx

# The declarative action families. `script` is the escape hatch (terminal-ness
# decided by what the script calls).
ACTIONS = ("block", "respond", "rewrite", "script")
TERMINAL_ACTIONS = ("block", "respond")


# --------------------------------------------------------------------------
# Path globbing: `*` within a segment, `**` across segments.
# --------------------------------------------------------------------------


def path_to_regex(glob: str) -> str:
    r"""Translate a path glob to an anchored regex string.

    `**` -> `.*` (crosses `/`); `*` -> `[^/]*` (within one segment); every other
    character is a literal. Anchored (fullmatch semantics). This is the single
    source of truth for path matching; `core/pathmatch.py` mirrors it byte-for-
    byte (guarded by tests/cli/test_wire_parity.py)."""
    out: list[str] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "^" + "".join(out) + "$"


def validate_path(glob: str) -> str | None:
    """Return an error message if `glob` is an unusable path pattern, else None.

    A path must be non-empty and start with `/` (request targets are absolute
    paths). We deliberately keep this permissive -- the segment/cross-segment
    semantics come from `*`/`**`, which are always legal."""
    if not glob:
        return "path must be a non-empty string"
    if not glob.startswith("/"):
        return f"path '{glob}' must start with '/'"
    return None


def compile_path(glob: str) -> re.Pattern:
    """Compile a validated path glob to a full-match regex."""
    return re.compile(path_to_regex(glob))


# --------------------------------------------------------------------------
# Compiled rule + rule set.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A compiled, ready-to-evaluate rule.

    Host/method/path matchers are pre-compiled; the action params carry whatever
    the action needs (declarative fields, or a compiled scripted scheme for
    `action="script"`). `visible` bundles enumeration + attribution (see the
    issue): a hit on a visible terminal rule self-identifies to the workspace; a
    hidden rule never does (but is always visible to the operator -- logs/audit).
    """
    name: str
    hosts: tuple[str, ...]                  # original spellings, for disclosure
    host_literals: frozenset[str]           # lowercased exact hosts
    # (original spelling, compiled glob) pairs -- the string is kept for /setup
    # disclosure and intercept enumeration, so nothing has to re-pair them later.
    host_patterns: tuple[tuple[str, "re.Pattern"], ...]
    methods: frozenset[str] | None          # uppercased; None = all methods
    path_glob: str | None                   # original, for disclosure
    path_rx: re.Pattern | None              # None = all paths
    action: str
    visible: bool
    # declarative action params (only the ones the action uses are set)
    status: int | None = None
    body: str | None = None
    headers: dict | None = None             # respond
    set_headers: dict | None = None         # rewrite request
    remove_headers: tuple[str, ...] | None = None
    resp_set_headers: dict | None = None    # rewrite response
    resp_remove_headers: tuple[str, ...] | None = None
    # action="script"
    scheme: object | None = None            # a ScriptedScheme (kind="rule")
    script_name: str | None = None          # for /admin/rule-test attribution

    @property
    def affects_request(self) -> bool:
        """True if the rule has a REQUEST-phase effect. A response-only rule (a
        rewrite touching only `resp_*` headers, or a script defining only
        `on_response`) has none, so it must not run -- or even log/audit -- in the
        request phase (else it emits a phantom `rewrite` marker and double-audits
        alongside its real response-phase hit)."""
        if self.action in TERMINAL_ACTIONS:
            return True
        if self.action == "rewrite":
            return bool(self.set_headers or self.remove_headers)
        if self.action == "script":
            return getattr(self.scheme, "has_on_request", False)
        return False

    @property
    def mutates_response(self) -> bool:
        """True if the rule can touch the RESPONSE: a response rewrite, or a
        script (which may define on_response). Response rules run after re-seal."""
        if self.action == "rewrite":
            return bool(self.resp_set_headers or self.resp_remove_headers)
        if self.action == "script":
            return getattr(self.scheme, "has_on_response", False)
        return False

    def matches(self, method: str, host: str, path: str) -> bool:
        """Does this rule match a request? host is matched case-insensitively;
        method case-insensitively; path against the query-stripped target."""
        h = host.lower()
        if h not in self.host_literals \
                and not any(rx.fullmatch(h) for (_, rx) in self.host_patterns):
            return False
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.path_rx is not None:
            if not self.path_rx.fullmatch(path.split("?", 1)[0]):
                return False
        return True


class RuleSet:
    """An ordered set of rules plus the host set they add to the intercept union.

    `request_rules(...)` / `response_rules(...)` return the matching rules in
    declaration order (response_rules only those that can touch the response).
    `intercept_literals` / `intercept_patterns` are folded into the credential
    intercept decision so a rule-only host is still TLS-terminated."""

    def __init__(self, rules: list[Rule] | None = None):
        self._rules: list[Rule] = rules or []
        self.intercept_literals: frozenset[str] = frozenset(
            h for r in self._rules for h in r.host_literals
        )
        # (original_pattern_str, compiled_rx) for intercept enumeration/decision.
        # Rule already carries the pairs, so no re-pairing/zip is needed.
        self.intercept_patterns: list[tuple[str, re.Pattern]] = [
            pair for r in self._rules for pair in r.host_patterns
        ]

    def __bool__(self) -> bool:
        return bool(self._rules)

    def all(self) -> list[Rule]:
        return list(self._rules)

    def request_rules(self, method: str, host: str, path: str) -> list[Rule]:
        return [r for r in self._rules
                if r.affects_request and r.matches(method, host, path)]

    def response_rules(self, method: str, host: str, path: str) -> list[Rule]:
        return [r for r in self._rules
                if r.mutates_response and r.matches(method, host, path)]

    def intercepts(self, sni: str) -> bool:
        sni = sni.lower()
        if sni in self.intercept_literals:
            return True
        return any(rx.fullmatch(sni) for (_, rx) in self.intercept_patterns)

    def intercept_hosts(self) -> set[str]:
        return set(self.intercept_literals) | {p for (p, _) in self.intercept_patterns}

    def disclosed_hosts(self) -> set[str]:
        """Hosts contributed by VISIBLE rules only -- the /setup enumeration
        surface. A host referenced ONLY by a HIDDEN rule is still intercepted
        (intercepts() uses the full set) but must NOT be enumerated here, or a
        hidden tripwire on a bindings-free host is passively discoverable via a
        single /setup read -- defeating the *unenumerated* half of the visibility
        contract (interception being detectable via the CA chain is the weaker,
        documented caveat; proactive name disclosure is not)."""
        out: set[str] = set()
        for r in self._rules:
            if not r.visible:
                continue
            out |= set(r.host_literals)
            out |= {orig for (orig, _) in r.host_patterns}
        return out

    def inward_rules(self) -> list[dict]:
        """Least-disclosure descriptors for /setup: name, hosts, methods, path,
        action -- never script source, never a rewrite's header values. HIDDEN
        rules are EXCLUDED entirely (unenumerated)."""
        out = []
        for r in self._rules:
            if not r.visible:
                continue
            out.append({
                "name": r.name,
                "hosts": list(r.hosts),
                "methods": sorted(r.methods) if r.methods is not None else None,
                "path": r.path_glob,
                "action": r.action,
            })
        return out

    def dry_run(self, method: str, host: str, path: str) -> list[dict]:
        """Authoritative rule-evaluation dry-run for `rule test --live`: the
        ordered matches for (method, host, path), with EXACT per-script phase read
        from each compiled scheme (`has_on_request`/`has_on_response`) -- which the
        host-side matcher can't know without Starlark. Mirrors the request-phase
        first-terminal-wins semantics of the CLI's `match_rules`, but because it
        knows a script's real hooks it need not be conservative: a response-only
        script is non-terminal (doesn't gate later rules), a request-active one
        `may_terminate`. Only block/respond are definitely terminal (stop)."""
        out: list[dict] = []
        conditional = False
        for r in self._rules:
            if not r.matches(method, host, path):
                continue
            item = {"name": r.name, "action": r.action, "visible": r.visible,
                    "conditional": conditional}
            if r.action == "script":
                has_req = bool(getattr(r.scheme, "has_on_request", False))
                has_resp = bool(getattr(r.scheme, "has_on_response", False))
                item["script"] = r.script_name
                item["phase"] = ("both" if has_req and has_resp else
                                 "request" if has_req else
                                 "response" if has_resp else None)
                item["terminal"] = False
                item["may_terminate"] = has_req
                out.append(item)
                if has_req:            # later rules only reached if it doesn't stop
                    conditional = True
                continue
            item["terminal"] = r.action in TERMINAL_ACTIONS
            item["may_terminate"] = False
            if r.status is not None:
                item["status"] = r.status
            out.append(item)
            if item["terminal"]:
                break
        return out


# --------------------------------------------------------------------------
# Synthetic responses + rule execution contexts.
# --------------------------------------------------------------------------


@dataclass
class SyntheticResponse:
    """A response a rule wants the proxy to send instead of forwarding. `kind`
    distinguishes a bare policy `block` (whose body/attribution the addon
    synthesizes from `visible`) from an author-supplied `respond` counterfeit
    (whose body is kept verbatim)."""
    kind: str                       # "block" | "respond"
    status: int
    body: str = ""
    headers: dict = field(default_factory=dict)


# A rule may not touch the request AUTHORITY. Binding selection happens on the
# pre-rewrite host, so setting or removing Host / :authority mid-pipeline would
# ship the original host's injected credential under a different authority -- a
# credential host-scope escape. Declarative rewrites are rejected at config load
# (config._reject_authority_rewrite); this guards the SCRIPTED path so a rule
# script's req_set_header("Host", ...) raises -> RuleError -> the addon's 502.
_FORBIDDEN_REWRITE_HEADERS = frozenset({"host", ":authority"})


def _reject_authority_header(name: str) -> None:
    if name.lower() in _FORBIDDEN_REWRITE_HEADERS:
        raise ValueError(
            f"a rule may not rewrite the request authority header {name!r} "
            f"(Host/:authority): it would send the injected credential under a "
            f"different host than the binding is scoped to")


class _RuleSink:
    """The terminal `block()`/`respond()` sinks + the `pending` slot shared by
    both rule ctx phases. A hook records the synthetic response it wants on
    `pending`; the addon reads `ctx.pending` and short-circuits. `reason` is for
    a script's own diagnostics -- the wire body/attribution is decided by the
    addon from the rule's visibility, not here. Each ctx `__init__` sets
    `self.pending = None` (the mixin has no `__init__`, so it stays out of the
    RequestCtx/ResponseCtx constructor chain)."""

    pending: "SyntheticResponse | None"

    def block(self, status: int = 403, reason: str | None = None) -> None:
        self.pending = SyntheticResponse("block", int(status))

    def respond(self, status: int, body: str = "", headers: dict | None = None) -> None:
        self.pending = SyntheticResponse("respond", int(status),
                                         body or "", dict(headers or {}))


class RuleRequestCtx(_RuleSink, RequestCtx):
    """Request-phase surface for a rule. Reuses the injection RequestCtx read/
    mutate primitives (so scripted rules share the flat `req_*` primitive API)
    but carries NO secret -- `secret()` is unreachable because the rule Starlark
    profile omits it, and this ctx is constructed with an empty secret map. Adds
    the `block`/`respond` sinks (via _RuleSink) and overrides `header_set`/
    `header_del` to reject Host/:authority mutation (credential scope escape)."""

    phase = "request"

    def __init__(self, request):
        super().__init__(request, {}, {}, None)
        self.pending: SyntheticResponse | None = None

    def header_set(self, name: str, value: str) -> None:
        _reject_authority_header(name)
        super().header_set(name, value)

    def header_del(self, name: str) -> None:
        _reject_authority_header(name)
        if name in self._req.headers:
            del self._req.headers[name]


class RuleResponseCtx(_RuleSink, ResponseCtx):
    """Response-phase surface for a rule. Reuses ResponseCtx (request reads are
    read-only; header/body mutation acts on the response). No minter, no secret.
    Adds the `block`/`respond` sinks (via _RuleSink) and a response `header_del`
    -- a script `respond`/`block` REPLACES the response wholesale."""

    phase = "response"

    def __init__(self, flow):
        super().__init__(flow, {}, {}, None, minter=None)
        self.pending: SyntheticResponse | None = None

    def header_del(self, name: str) -> None:
        if name in self._flow.response.headers:
            del self._flow.response.headers[name]


class RuleError(Exception):
    """A scripted rule hook failed. Distinct from injector-script failure: rule
    scripts hold no secret, so the message is NOT sanitized -- the addon renders
    a `502 credproxy: rule 'NAME' failed` and may log the full cause."""


def apply_request_rule(rule: Rule, ctx: RuleRequestCtx) -> bool:
    """Apply one rule's REQUEST-phase effect to `ctx`. Returns True if the rule
    is terminal (a synthetic response was set on `ctx.pending`); a non-terminal
    rewrite returns False. Raises RuleError if a script hook fails (fail closed).
    """
    action = rule.action
    if action == "block":
        ctx.block(rule.status or 403)
        return True
    if action == "respond":
        ctx.respond(rule.status or 200, rule.body or "", rule.headers)
        return True
    if action == "rewrite":
        for name, value in (rule.set_headers or {}).items():
            ctx.header_set(name, value)
        for name in (rule.remove_headers or ()):
            ctx.header_del(name)
        return False
    if action == "script":
        _run_script(rule, "on_request", ctx)
        return ctx.pending is not None
    raise RuleError(f"rule '{rule.name}' has unknown action {action!r}")


def apply_response_rule(rule: Rule, ctx: RuleResponseCtx) -> bool:
    """Apply one rule's RESPONSE-phase effect. Only rules that can touch the
    response reach here (see RuleSet.response_rules). Returns True if terminal
    (the response was replaced). Raises RuleError on a script failure."""
    action = rule.action
    if action == "rewrite":
        for name, value in (rule.resp_set_headers or {}).items():
            ctx.header_set(name, value)
        for name in (rule.resp_remove_headers or ()):
            ctx.header_del(name)
        return False
    if action == "script":
        _run_script(rule, "on_response", ctx)
        return ctx.pending is not None
    # block/respond are request-terminal; they never reach the response phase.
    return False


def _run_script(rule: Rule, hook: str, ctx) -> None:
    """Invoke a scripted rule's hook, translating any failure into RuleError so
    the addon fails closed toward the policy (a 502, never proceed-un-governed).
    Rule scripts carry no secret, so the underlying message is safe to surface."""
    scheme = rule.scheme
    fn = getattr(scheme, hook, None)
    if fn is None:
        return
    try:
        fn(ctx)
    except Exception as e:
        raise RuleError(f"rule '{rule.name}' {hook} failed: {e}") from e
