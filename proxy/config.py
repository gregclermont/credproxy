"""Proxy configuration: intercept set + per-host injection transforms.

The proxy receives an already-resolved config (literal secret values, no
template references) via POST /admin/config. The host CLI is the supported
producer; it resolves each binding's secret from its provider before posting.

This module validates the parsed dict and produces a BindingCredentials
instance. Wire schema (scheme-aware):

    {
      "bindings": [
        {
          "name":        "github-git",            # non-empty, unique
          "hosts":       ["github.com"],           # non-empty list of strings
          "scheme":      "basic",                  # a key in schemes.SCHEMES
          "params":      {"header": "Authorization"},  # optional, scheme-defined
          "secret":      {"value": "<real>"},      # slot -> resolved value
          "placeholder": "ghp_xxx...",             # substitute schemes; the
                                                   #   inert token to find/swap
          "env":         "GITHUB_TOKEN"            # optional; null/absent ok
        }
      ]
    }

`secret` is a slot->value table (single-slot substitute schemes use the
`value` slot). The proxy dispatches on `scheme`; the placeholder, params, and
resolved secrets are bundled into a Transform the scheme's `on_request` acts
through.

Uniqueness constraints:
  - `name` is unique across bindings.
  - the (host, wire-location) pair is unique — two bindings can't both write
    the same header (or both write the body) on the same host.

A `hosts` entry is either a literal hostname (exact match) or a glob pattern
containing `*` (see hostmatch.py): `*.amazonaws.com` scopes a binding to every
AWS region/service endpoint. Literals keep the O(1) dict path; patterns are
scanned linearly.

Credentials API:
  - `intercepts(sni)`    -> bool: should this SNI be TLS-terminated? Checks
    literals, then glob patterns, then the live runtime layer. The decision
    seam (vs. `intercept_hosts`, which only enumerates for display).
  - `intercept_hosts()`  -> set[str]: literals + pattern strings + live runtime
    hosts, for /setup disclosure and logging (NOT the decision -- a pattern
    can't enumerate the SNIs it matches).
  - `transforms_for(host)` -> list[Transform]: transforms active for a host,
    static (pushed) layer plus a runtime-augmentable layer (the re-seal seam;
    empty today).
  - `inward_bindings()`  -> list[InwardBinding]: least-disclosure descriptors
    for /setup (no secret values, no provider/secret-id).
"""
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import audit
import hostmatch
import rules as rules_mod
import schemes
from rules import Rule, RuleSet
from schemes import Scheme

_SECRET_REF = re.compile(r"\$\{secret:([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class Transform:
    """A compiled, ready-to-run injection for one binding: the scheme object,
    its params, the inert placeholder (substitute family), and the resolved
    secret slots the scheme reads via ctx.secret()."""
    name: str
    scheme: Scheme
    params: dict
    placeholder: str | None
    secrets: dict[str, str]


@dataclass(frozen=True)
class InwardBinding:
    """Workspace-safe binding descriptor: no secret value, no provider/secret-id."""
    name: str
    placeholder: str | None
    env: str | None
    scheme: str
    params: dict
    hosts: list[str]


class Credentials(Protocol):
    def intercepts(self, sni: str | None) -> bool: ...
    def intercept_hosts(self) -> set[str]: ...
    def disclosed_intercept_hosts(self) -> set[str]: ...
    def transforms_for(self, host: str) -> list[Transform]: ...
    def inward_bindings(self) -> list[InwardBinding]: ...
    def rule_set(self) -> RuleSet: ...


class BindingCredentials:
    """Credentials built from the bindings wire format.

    The host->transforms map is the *static* layer pushed via /admin/config.
    `transforms_for` overlays a *runtime* layer (re-seal seam): the
    substitution set must be a function over (static + runtime-augmentable),
    never baked immutable at push time, so dynamically-minted placeholders can
    be registered later. The runtime layer is empty until re-seal lands.
    """

    def __init__(
        self,
        hosts: dict[str, list[Transform]],
        bindings: list[InwardBinding] | None = None,
        patterns: list[tuple[str, "re.Pattern", Transform]] | None = None,
        rules: RuleSet | None = None,
        clock=time.monotonic,
    ):
        self._hosts = hosts
        # The rules layer (traffic governance). Its host set joins the intercept
        # UNION below, so a host with only rules is still TLS-terminated.
        self._rules = rules if rules is not None else RuleSet()
        # Glob-pattern layer (hostmatch): (pattern_str, compiled_regex,
        # Transform), in config order. Scanned linearly after the literal dict
        # hit, so a request matching several patterns applies them in config
        # order (last writer to a given header wins). Usually empty.
        self._patterns = patterns or []
        # Runtime layer: host -> list of (Transform, expires_at | None). Re-seal
        # schemes mint these at response time with a TTL; expired entries are
        # pruned lazily on read (no background task). expires_at is in `clock`
        # units (monotonic by default; injectable for tests).
        self._runtime: dict[str, list[tuple[Transform, float | None]]] = {}
        self._clock = clock
        self._bindings: list[InwardBinding] = bindings or []

    def intercepts(self, sni: str | None) -> bool:
        """Should this SNI be TLS-terminated? The decision seam used by the
        addon: exact literal, then glob pattern, then a live runtime host. A
        pattern set can't be enumerated, so this is a predicate, not membership
        on `intercept_hosts()`."""
        if not sni:
            return False
        sni = sni.lower()                 # DNS/SNI names are case-insensitive
        if sni in self._hosts:
            return True
        if any(rx.fullmatch(sni) for (_, rx, _) in self._patterns):
            return True
        # Intercept UNION: a rule-only host (no binding) must still be terminated,
        # or the proxy never sees the request the rule governs.
        if self._rules.intercepts(sni):
            return True
        return bool(self._live(sni))

    def intercept_hosts(self) -> set[str]:
        live = {h for h in list(self._runtime) if self._live(h)}
        return (set(self._hosts) | {p for (p, _, _) in self._patterns}
                | self._rules.intercept_hosts() | live)

    def disclosed_intercept_hosts(self) -> set[str]:
        """`intercept_hosts()` minus hosts referenced ONLY by hidden rules -- the
        workspace-facing /setup enumeration surface (least disclosure). Binding
        and live re-seal hosts are always disclosed (bindings are enumerated in
        /setup anyway); only rule hosts are visibility-filtered. The decision path
        (`intercepts()`) still uses the full set, so a hidden rule still fires."""
        live = {h for h in list(self._runtime) if self._live(h)}
        return (set(self._hosts) | {p for (p, _, _) in self._patterns}
                | self._rules.disclosed_hosts() | live)

    def rule_set(self) -> RuleSet:
        return self._rules

    def transforms_for(self, host: str) -> list[Transform]:
        host = host.lower()               # DNS hostnames are case-insensitive
        out = list(self._hosts.get(host, []))
        if self._patterns:
            out += [t for (_, rx, t) in self._patterns if rx.fullmatch(host)]
        return out + self._live(host)

    def register_runtime(self, host: str, transform: Transform,
                         ttl: float | None = None) -> None:
        """Add a runtime transform for `host` (the re-seal mint seam), optionally
        expiring `ttl` seconds from now. ttl=None means it never expires."""
        expires_at = (self._clock() + ttl) if ttl is not None else None
        self._runtime.setdefault(host.lower(), []).append((transform, expires_at))

    def adopt_runtime(self, other) -> None:
        """Carry `other`'s still-live runtime (re-seal) transforms into this
        instance. Used when POST /admin/config swaps creds: the STATIC pushed
        layer is replaced, but a minted token registered at re-seal time (a
        dynamic placeholder with a TTL) must survive the swap -- otherwise a
        routine re-push (apply/start) silently drops an in-flight minted token,
        making it unresolvable until the next mint. The swap set is 'static +
        runtime-augmentable', never baked immutable at push time (CLAUDE.md).

        Absolute `expires_at` values transfer directly: both instances share the
        same monotonic clock (same process), so a copied entry keeps its original
        expiry. Defensive against a duck-typed `other` with no runtime layer."""
        other_runtime = getattr(other, "_runtime", None)
        if not other_runtime:
            return
        now = self._clock()
        for host, entries in other_runtime.items():
            live = [(t, e) for (t, e) in entries if e is None or e > now]
            if live:
                self._runtime.setdefault(host, []).extend(live)

    def _live(self, host: str) -> list[Transform]:
        """Non-expired runtime transforms for `host`, pruning expired ones in
        place so the store can't grow without bound."""
        entries = self._runtime.get(host)
        if not entries:
            return []
        now = self._clock()
        live = [(t, e) for (t, e) in entries if e is None or e > now]
        if len(live) != len(entries):
            if live:
                self._runtime[host] = live
            else:
                del self._runtime[host]
        return [t for (t, _) in live]

    def inward_bindings(self) -> list[InwardBinding]:
        return list(self._bindings)


class RuntimeMinter:
    """Registers a runtime-derived secret as a dynamic placeholder (re-seal).

    `mint(value, ttl, api_hosts, header)` generates a placeholder, registers a
    bearer-substitute swap (placeholder -> value) on each API host with the
    given TTL, and returns the placeholder. The data-plane swap reuses the
    built-in bearer scheme: a dynamic placeholder is just a static one
    registered at runtime, so the request-phase injection path is unchanged.

    Lives here (not on ResponseCtx) because building a Transform couples to
    config; the instance is injected into ResponseCtx so schemes.py stays free
    of a config import."""

    def __init__(self, creds: "BindingCredentials", generate_placeholder,
                 source_binding: str | None = None,
                 source_host: str | None = None,
                 source_scheme: str | None = None):
        self._creds = creds
        self._generate = generate_placeholder
        # The re-seal binding (and token-endpoint host + scheme) this mint is on
        # behalf of. `source_binding` is named into the runtime transform so the
        # LATER injection audit event (when the minted placeholder is used on an
        # API host) carries `reseal:<source>` and correlates with the `reseal`
        # mint event emitted here; `source_scheme`/`source_host` round out that
        # event's fields (parity with the pre-move addon-side emit).
        self._source_binding = source_binding
        self._source_host = source_host
        self._source_scheme = source_scheme

    def mint(self, value: str, ttl: float | None, api_hosts, header: str = "Authorization") -> str:
        if not api_hosts:
            raise ValueError("mint requires at least one api_host (binding param 'api_hosts')")
        # Last-line guard: a non-finite or negative TTL would register a permanent
        # (or already-expired) runtime entry. ttl=None is the intentional
        # never-expires case.
        if ttl is not None and (not math.isfinite(ttl) or ttl < 0):
            raise ValueError(f"mint ttl must be a non-negative finite number (got {ttl!r})")
        placeholder = self._generate()
        name = (f"reseal:{self._source_binding}" if self._source_binding
                else f"reseal:{placeholder[:16]}")
        transform = Transform(
            name=name,
            scheme=schemes.SCHEMES["bearer"],
            params={"header": header},
            placeholder=placeholder,
            secrets={"value": value},
        )
        for host in api_hosts:
            self._creds.register_runtime(host, transform, ttl=ttl)
        # Emit the mint audit HERE, not on the scheme's return value: a re-seal
        # SCRIPT that mints but doesn't `return True` would otherwise register the
        # swap silently, leaving later `inject` events uncorrelated. This tracks
        # the actual registration.
        audit.emit("reseal", binding=self._source_binding,
                   scheme=self._source_scheme, host=self._source_host,
                   api_hosts=list(api_hosts), outcome="minted")
        return placeholder


class ConfigError(Exception):
    """Raised on validation failure. Callers decide how to handle:
    main.py SystemExits at startup; the admin endpoint returns 400."""


def _fail(msg: str) -> None:
    raise ConfigError(f"[config] {msg}")


def _build_scripted_scheme(entry: dict, source: str, where: str):
    """Compile a pushed `.star` source into a ScriptedScheme (scheme="script").

    The wire carries the script source plus the metadata the CLI couldn't infer
    (family/slots/location). starlark_runtime is imported lazily so this module
    stays importable where starlark is absent (e.g. the host-side drift test)."""
    src = entry.get("script_source")
    if not isinstance(src, str) or not src:
        _fail(f"{source}: {where} scheme 'script' needs a non-empty 'script_source'")
    name = entry.get("script")
    if not isinstance(name, str) or not name:
        name = "script"
    api = entry.get("api", 1)
    if not isinstance(api, int) or isinstance(api, bool):
        _fail(f"{source}: {where}.api must be an integer")
    family = entry.get("family")
    if family not in ("substitute", "sign"):
        _fail(f"{source}: {where}.family must be 'substitute' or 'sign'")
    slots = entry.get("slots")
    if not isinstance(slots, list) or not slots \
            or not all(isinstance(s, str) and s for s in slots):
        _fail(f"{source}: {where}.slots must be a non-empty array of strings")
    location_kind = entry.get("location_kind", "header")
    if location_kind not in ("header", "body"):
        _fail(f"{source}: {where}.location_kind must be 'header' or 'body'")
    header_default = entry.get("header_default")
    if header_default is not None and not isinstance(header_default, str):
        _fail(f"{source}: {where}.header_default must be a string or null")
    try:
        from starlark_runtime import SUPPORTED_API_VERSIONS, ScriptedScheme
    except Exception as e:  # pragma: no cover - starlark always present in proxy
        _fail(f"{source}: scripted schemes require the starlark runtime ({e})")
    if api not in SUPPORTED_API_VERSIONS:
        _fail(f"{source}: {where} script '{name}' declares api version {api}, "
              f"unsupported by this proxy (implements "
              f"{', '.join(str(v) for v in sorted(SUPPORTED_API_VERSIONS))})")
    try:
        # A compile error here is about the host's own script source (no secret
        # is in scope at compile time), so it is safe to surface.
        return ScriptedScheme(
            name, src, family=family, slots=tuple(slots),
            location_kind=location_kind, header_default=header_default,
        )
    except Exception as e:
        _fail(f"{source}: {where} script '{name}' failed to compile: {e}")


# Fields allowed on a rule, keyed by action. `_COMMON_RULE_FIELDS` are always
# allowed; anything else on an entry is a validation error (400-with-path), so a
# misplaced param (a `body` on a `block`, a `set_headers` on a `respond`) is
# caught at push rather than silently ignored.
_COMMON_RULE_FIELDS = frozenset({"name", "hosts", "methods", "path", "action",
                                 "visible"})
_RULE_ACTION_FIELDS = {
    "block": frozenset({"status"}),
    "respond": frozenset({"status", "body", "headers"}),
    "rewrite": frozenset({"set_headers", "remove_headers",
                          "resp_set_headers", "resp_remove_headers"}),
    "script": frozenset({"script", "script_source", "api"}),
}
# Per-family default for the `visible` flag when omitted: terminal actions are
# diagnosable-by-default (attributed + enumerated); rewrite/script default hidden
# (they emit no attribution anyway and enumeration usually leaks what's hidden).
_VISIBLE_DEFAULT = {"block": True, "respond": True, "rewrite": False,
                    "script": False}

# A rewrite may not touch the request AUTHORITY (Host / :authority): it would ship
# the original host's injected credential under a different authority -- a
# credential host-scope escape. Rejected at load; the CLI mirrors at `rule add`,
# and RuleRequestCtx blocks the scripted path. The name set lives once in rules.py
# (this is the same proxy deploy unit) -- reference it, don't re-declare.
def _reject_authority_rewrite(set_headers, remove_headers, source: str,
                              where: str) -> None:
    for name in list(set_headers or {}) + list(remove_headers or ()):
        if name.lower() in rules_mod._FORBIDDEN_REWRITE_HEADERS:
            _fail(f"{source}: {where} may not rewrite the request authority "
                  f"header '{name}' (Host/:authority): it would send the injected "
                  f"credential under a different host than the binding is scoped "
                  f"to -- scope is pinned by the host match")


def _str_map(value, source: str, where: str) -> dict:
    """Validate a header map (str -> str, both non-empty). Header NAMES may be
    empty-checked; values may be empty strings? We require non-empty names but
    allow empty values (a header set to '')."""
    if not isinstance(value, dict):
        _fail(f"{source}: {where} must be an object of string->string")
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            _fail(f"{source}: {where} has a non-string or empty header name")
        if not isinstance(v, str):
            _fail(f"{source}: {where}['{k}'] must be a string")
    return dict(value)


def _str_list(value, source: str, where: str) -> tuple:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        _fail(f"{source}: {where} must be an array of non-empty strings")
    return tuple(value)


def _build_rule_scheme(entry: dict, source: str, where: str):
    """Compile a pushed rule `.star` source into a kind='rule' ScriptedScheme.

    Mirrors _build_scripted_scheme, but the rule profile is restricted (no
    secret/mint/crypto) and its errors are unsanitized. Returns (scheme, name).
    """
    src = entry.get("script_source")
    if not isinstance(src, str) or not src:
        _fail(f"{source}: {where} action 'script' needs a non-empty 'script_source'")
    name = entry.get("script")
    if not isinstance(name, str) or not name:
        name = "rule"
    api = entry.get("api", 1)
    if not isinstance(api, int) or isinstance(api, bool):
        _fail(f"{source}: {where}.api must be an integer")
    try:
        from starlark_runtime import SUPPORTED_API_VERSIONS, ScriptedScheme
    except Exception as e:  # pragma: no cover - starlark always present in proxy
        _fail(f"{source}: scripted rules require the starlark runtime ({e})")
    if api not in SUPPORTED_API_VERSIONS:
        _fail(f"{source}: {where} rule script '{name}' declares api version {api}, "
              f"unsupported by this proxy (implements "
              f"{', '.join(str(v) for v in sorted(SUPPORTED_API_VERSIONS))})")
    try:
        return ScriptedScheme(name, src, kind="rule"), name
    except Exception as e:
        # Safe to surface: a rule script holds no secret at compile OR run time.
        _fail(f"{source}: {where} rule script '{name}' failed to compile: {e}")


def _load_rules(raw_rules, source: str) -> RuleSet:
    """Validate the `rules` array and compile it into a RuleSet. Same
    400-with-path rigor as bindings: unknown action, misplaced/missing param,
    bad host/path glob, unknown-version or uncompilable script each fail here."""
    if not isinstance(raw_rules, list):
        _fail(f"{source}: `rules` must be an array")

    names_seen: set[str] = set()
    compiled: list[Rule] = []
    for i, entry in enumerate(raw_rules):
        where = f"rules[{i}]"
        if not isinstance(entry, dict):
            _fail(f"{source}: {where} must be an object")

        # --- name ---
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            _fail(f"{source}: {where}.name must be a non-empty string")
        if name in names_seen:
            _fail(f"{source}: duplicate rule name '{name}'")
        names_seen.add(name)

        # --- action (validated first: it gates the allowed field set) ---
        action = entry.get("action")
        if action not in rules_mod.ACTIONS:
            _fail(f"{source}: {where}.action must be one of "
                  f"{', '.join(rules_mod.ACTIONS)} (got {action!r})")
        allowed = _COMMON_RULE_FIELDS | _RULE_ACTION_FIELDS[action]
        extra = set(entry) - allowed
        if extra:
            _fail(f"{source}: {where} has field(s) not valid for action "
                  f"'{action}': {', '.join(sorted(extra))}")

        # --- hosts (literals + globs) ---
        rhosts = entry.get("hosts")
        if not isinstance(rhosts, list) or not rhosts \
                or not all(isinstance(h, str) and h for h in rhosts):
            _fail(f"{source}: {where}.hosts must be a non-empty array of strings")
        host_literals = set()
        host_patterns = []
        for h in rhosts:
            if hostmatch.is_pattern(h):
                err = hostmatch.validate_pattern(h)
                if err:
                    _fail(f"{source}: {where}.hosts: {err}")
                host_patterns.append((h, hostmatch.compile_pattern(h.lower())))
            else:
                host_literals.add(h.lower())

        # --- methods (optional; absent = all, but an EMPTY list would match no
        #     method -> a silent dead rule, so reject it) ---
        methods = entry.get("methods")
        if methods is None:
            method_set = None
        else:
            method_list = _str_list(methods, source, f"{where}.methods")
            if not method_list:
                _fail(f"{source}: {where}.methods must be a non-empty array "
                      f"(omit it entirely to match all methods)")
            method_set = frozenset(m.upper() for m in method_list)

        # --- path (optional) ---
        path = entry.get("path")
        if path is None:
            path_rx = None
        else:
            if not isinstance(path, str):
                _fail(f"{source}: {where}.path must be a string")
            perr = rules_mod.validate_path(path)
            if perr:
                _fail(f"{source}: {where}.path: {perr}")
            path_rx = rules_mod.compile_path(path)

        # --- visible (optional; per-family default) ---
        visible = entry.get("visible")
        if visible is None:
            visible = _VISIBLE_DEFAULT[action]
        elif not isinstance(visible, bool):
            _fail(f"{source}: {where}.visible must be a boolean")

        kwargs = {}
        scheme = None
        script_name = None
        if action == "block":
            kwargs["status"] = _rule_status(entry, source, where, default=403)
        elif action == "respond":
            status = entry.get("status")
            if status is None:
                _fail(f"{source}: {where} action 'respond' requires a 'status'")
            kwargs["status"] = _rule_status(entry, source, where, default=None)
            body = entry.get("body")
            if body is not None and not isinstance(body, str):
                _fail(f"{source}: {where}.body must be a string")
            kwargs["body"] = body
            headers = entry.get("headers")
            kwargs["headers"] = (_str_map(headers, source, f"{where}.headers")
                                 if headers is not None else None)
        elif action == "rewrite":
            sh = entry.get("set_headers")
            rh = entry.get("remove_headers")
            rsh = entry.get("resp_set_headers")
            rrh = entry.get("resp_remove_headers")
            # A present-but-EMPTY op ({} / []) is `not None` but does nothing, so
            # test truthiness -- else an empty rewrite loads clean yet only flips
            # the host to intercepted (parity with the `methods` non-empty check).
            if not (sh or rh or rsh or rrh):
                _fail(f"{source}: {where} action 'rewrite' needs at least one "
                      f"NON-EMPTY of set_headers/remove_headers/resp_set_headers/"
                      f"resp_remove_headers")
            kwargs["set_headers"] = (_str_map(sh, source, f"{where}.set_headers")
                                     if sh is not None else None)
            kwargs["remove_headers"] = (_str_list(rh, source, f"{where}.remove_headers")
                                        if rh is not None else None)
            kwargs["resp_set_headers"] = (_str_map(rsh, source, f"{where}.resp_set_headers")
                                          if rsh is not None else None)
            kwargs["resp_remove_headers"] = (_str_list(rrh, source, f"{where}.resp_remove_headers")
                                             if rrh is not None else None)
            _reject_authority_rewrite(kwargs["set_headers"],
                                      kwargs["remove_headers"], source, where)
        elif action == "script":
            scheme, script_name = _build_rule_scheme(entry, source, where)

        compiled.append(Rule(
            name=name,
            hosts=tuple(rhosts),
            host_literals=frozenset(host_literals),
            host_patterns=tuple(host_patterns),
            methods=method_set,
            path_glob=path,
            path_rx=path_rx,
            action=action,
            visible=visible,
            scheme=scheme,
            script_name=script_name,
            **kwargs,
        ))

    return RuleSet(compiled)


def _rule_status(entry: dict, source: str, where: str, default):
    status = entry.get("status", default)
    if status is default and default is not None:
        return default
    if not isinstance(status, int) or isinstance(status, bool) \
            or not (100 <= status <= 599):
        _fail(f"{source}: {where}.status must be an integer HTTP status "
              f"(100-599), got {status!r}")
    return status


def _check_unresolved(value: str, source: str, where: str) -> None:
    m = _SECRET_REF.search(value)
    if m:
        _fail(
            f"{source}: {where} contains unresolved ${{secret:{m.group(1)}}} "
            f"-- the caller is expected to resolve before posting"
        )


def load_resolved(raw: Any, source: str = "<resolved>") -> BindingCredentials:
    """Build credentials from a parsed dict (already-resolved values).

    `raw` must conform to the bindings schema at the top of this module. Any
    remaining `${secret:...}` text in a placeholder or secret value is a
    validation error -- secret resolution is the caller's responsibility.
    """
    if not isinstance(raw, dict) or "bindings" not in raw:
        _fail(f"{source}: missing top-level `bindings:` key")

    bindings_raw = raw["bindings"]
    if not isinstance(bindings_raw, list):
        _fail(f"{source}: `bindings` must be an array")

    names_seen: set[str] = set()
    # (host, location) -> {"unconditional": name|None, "by_ph": {placeholder: name}}.
    # Two bindings may share a wire location ONLY if each is disambiguated by a
    # distinct, non-None placeholder (the request carries one placeholder, so the
    # matching binding is unambiguous -- this is what lets several re-seal
    # bindings share one token endpoint). A binding with no placeholder writes
    # unconditionally and can't share a location with anything.
    loc_seen: dict[tuple, dict] = {}
    hosts: dict[str, list[Transform]] = {}
    # Glob-pattern bindings: (pattern_str, compiled_regex, Transform), config
    # order. The (host, location) uniqueness check above keys on the host
    # *string*, so it catches two bindings sharing an identical pattern but not
    # two *different* patterns that happen to overlap (e.g. `*.amazonaws.com` vs
    # `s3.*.amazonaws.com`); that's resolved at request time by transforms_for's
    # config-order, last-writer-wins.
    patterns: list[tuple[str, re.Pattern, Transform]] = []
    inward: list[InwardBinding] = []

    for i, entry in enumerate(bindings_raw):
        where = f"bindings[{i}]"
        if not isinstance(entry, dict):
            _fail(f"{source}: {where} must be an object")

        # --- name ---
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            _fail(f"{source}: {where}.name must be a non-empty string")
        if name in names_seen:
            _fail(f"{source}: duplicate binding name '{name}'")
        names_seen.add(name)

        # --- hosts (literals + glob patterns) ---
        binding_hosts = entry.get("hosts")
        if not isinstance(binding_hosts, list) or not binding_hosts \
                or not all(isinstance(h, str) and h for h in binding_hosts):
            _fail(f"{source}: {where}.hosts must be a non-empty array of strings")
        # A host with `*` is a glob pattern; validate it strictly here (the
        # CLI mirrors this at `binding add`, but the proxy is the boundary).
        for h in binding_hosts:
            if hostmatch.is_pattern(h):
                err = hostmatch.validate_pattern(h)
                if err:
                    _fail(f"{source}: {where}.hosts: {err}")

        # --- scheme ---
        # Built-in schemes come from the registry; "script" builds a sandboxed
        # ScriptedScheme from the pushed source. Both duck-type schemes.Scheme,
        # so the slot/placeholder/location checks below are uniform.
        scheme_name = entry.get("scheme")
        if scheme_name == "script":
            scheme = _build_scripted_scheme(entry, source, where)
        elif isinstance(scheme_name, str) and scheme_name in schemes.SCHEMES:
            scheme = schemes.SCHEMES[scheme_name]
        else:
            _fail(
                f"{source}: {where}.scheme must be one of "
                f"{', '.join(sorted(schemes.SCHEMES))}, 'script' (got {scheme_name!r})"
            )

        # --- params (optional) ---
        params = entry.get("params", {})
        if not isinstance(params, dict):
            _fail(f"{source}: {where}.params must be an object")
        # Param values are NON-EMPTY strings (e.g. `header`) or arrays of
        # non-empty strings (e.g. a re-seal scheme's `api_hosts`). A wrong type --
        # or an empty scalar like `{"header": ""}`, which validates clean yet
        # never matches at request time -> silent no-inject -- is rejected here.
        for pk, pv in params.items():
            if isinstance(pv, str) and pv:
                continue
            if isinstance(pv, list) and all(isinstance(x, str) and x for x in pv):
                continue
            _fail(f"{source}: {where}.params['{pk}'] must be a non-empty string "
                  f"or array of non-empty strings")
        # Required params: some schemes (re-seal) declare params they cannot run
        # without. For re-seal that gap is a fail-OPEN -- on_response would raise
        # and the original token-endpoint response (carrying the real minted
        # token) would otherwise reach the workspace -- so reject the binding at
        # load rather than at the first token response. A present-but-empty value
        # (missing key, "", or []) counts as absent.
        for rp in getattr(scheme, "required_params", ()):
            pv = params.get(rp)
            if pv is None or (isinstance(pv, (str, list)) and len(pv) == 0):
                _fail(f"{source}: {where} scheme '{scheme_name}' requires a "
                      f"non-empty param '{rp}'")

        # --- secret (slot -> value) ---
        secret = entry.get("secret")
        if not isinstance(secret, dict) or not secret:
            _fail(f"{source}: {where}.secret must be a non-empty object of slot->value")
        for slot, val in secret.items():
            if not isinstance(val, str) or not val:
                _fail(f"{source}: {where}.secret['{slot}'] must be a non-empty string")
            _check_unresolved(val, source, f"{where}.secret['{slot}']")
        # Slots must match the scheme's declared set exactly -- missing slots
        # break injection; extra slots mean stray resolved secret values held in
        # memory. Symmetric with the CLI's validate().
        want = set(scheme.slots)
        got = set(secret)
        if got != want:
            _fail(
                f"{source}: {where} scheme '{scheme_name}' needs secret slot(s) "
                f"{{{', '.join(sorted(want))}}}, got {{{', '.join(sorted(got))}}}"
            )

        # --- placeholder (required for the substitute family) ---
        placeholder = entry.get("placeholder")
        if scheme.family == "substitute":
            if not isinstance(placeholder, str) or not placeholder:
                _fail(f"{source}: {where}.placeholder must be a non-empty string")
            _check_unresolved(placeholder, source, f"{where}.placeholder")
        elif placeholder is not None and (not isinstance(placeholder, str) or not placeholder):
            _fail(f"{source}: {where}.placeholder must be a non-empty string or absent")

        # --- env (optional) ---
        env = entry.get("env")
        if env is not None and (not isinstance(env, str) or not env):
            _fail(f"{source}: {where}.env must be a non-empty string or absent/null")

        # --- (host, location) uniqueness, disambiguated by placeholder ---
        # Key the collision check on the lower-cased host (DNS is
        # case-insensitive), so two bindings on `API.example.com` and
        # `api.example.com` writing one location are caught here, not silently
        # merged after `transforms_for` lower-cases at match time.
        loc = schemes.location_key(scheme, params)
        for host in binding_hosts:
            group = loc_seen.setdefault((host.lower(), loc),
                                        {"unconditional": None, "by_ph": {}})
            if placeholder is None:
                # Writes the location unconditionally -> can't coexist there.
                other = group["unconditional"] or next(iter(group["by_ph"].values()), None)
                if other is not None:
                    _fail(
                        f"{source}: bindings '{other}' and '{name}' both write "
                        f"{loc[0]} on host '{host}' (a binding with no placeholder "
                        f"writes unconditionally and can't share a wire location)"
                    )
                group["unconditional"] = name
            else:
                if group["unconditional"] is not None:
                    _fail(
                        f"{source}: bindings '{group['unconditional']}' and '{name}' "
                        f"both write {loc[0]} on host '{host}' (a binding with no "
                        f"placeholder writes unconditionally and can't share a "
                        f"wire location)"
                    )
                # Placeholders sharing a wire location must be DISJOINT, not just
                # distinct: substitution is sequential str.replace, so if one
                # placeholder is a substring of another (`ph` vs `ph2`), replacing
                # the shorter first corrupts the longer -> the wrong binding fires.
                for existing_ph, existing_name in group["by_ph"].items():
                    if existing_ph == placeholder:
                        _fail(
                            f"{source}: bindings '{existing_name}' and '{name}' "
                            f"both write {loc[0]} on host '{host}' with the same "
                            f"placeholder '{placeholder}'"
                        )
                    if existing_ph in placeholder or placeholder in existing_ph:
                        _fail(
                            f"{source}: bindings '{existing_name}' and '{name}' "
                            f"share {loc[0]} on host '{host}' but their placeholders "
                            f"'{existing_ph}' and '{placeholder}' overlap (one is a "
                            f"substring of the other); sequential substitution would "
                            f"corrupt the other"
                        )
                group["by_ph"][placeholder] = name

        transform = Transform(
            name=name,
            scheme=scheme,
            params=params,
            placeholder=placeholder,
            secrets=dict(secret),
        )
        # Store match keys lower-cased (DNS is case-insensitive) so they agree
        # with the lower-cased lookup in intercepts/transforms_for. inward (below)
        # keeps the original casing for /setup display.
        for host in binding_hosts:
            h = host.lower()
            if hostmatch.is_pattern(h):
                patterns.append((h, hostmatch.compile_pattern(h), transform))
            else:
                hosts.setdefault(h, []).append(transform)

        # Re-seal: a scheme may need extra hosts TLS-terminated (the API hosts
        # where a minted token is later used) even though no static transform
        # writes there -- the runtime layer fills in once a token is minted.
        extra = getattr(scheme, "extra_intercept_hosts", None)
        if extra is not None:
            for h in extra(params):
                if not isinstance(h, str) or not h:
                    _fail(f"{source}: {where} scheme '{scheme_name}' returned an "
                          f"invalid extra-intercept host {h!r}")
                hosts.setdefault(h.lower(), [])

        inward.append(InwardBinding(
            name=name,
            placeholder=placeholder,
            env=env,
            scheme=scheme_name,
            params=params,
            hosts=list(binding_hosts),
        ))

    # Rules ride the same wire config next to bindings (optional array). Their
    # host set joins the intercept union in BindingCredentials.
    rule_set = _load_rules(raw.get("rules", []), source)

    return BindingCredentials(hosts, inward, patterns, rules=rule_set)
