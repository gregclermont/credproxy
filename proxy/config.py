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
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import hostmatch
import schemes
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
    def transforms_for(self, host: str) -> list[Transform]: ...
    def inward_bindings(self) -> list[InwardBinding]: ...


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
        clock=time.monotonic,
    ):
        self._hosts = hosts
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
        if sni in self._hosts:
            return True
        if any(rx.fullmatch(sni) for (_, rx, _) in self._patterns):
            return True
        return bool(self._live(sni))

    def intercept_hosts(self) -> set[str]:
        live = {h for h in list(self._runtime) if self._live(h)}
        return set(self._hosts) | {p for (p, _, _) in self._patterns} | live

    def transforms_for(self, host: str) -> list[Transform]:
        out = list(self._hosts.get(host, []))
        if self._patterns:
            out += [t for (_, rx, t) in self._patterns if rx.fullmatch(host)]
        return out + self._live(host)

    def register_runtime(self, host: str, transform: Transform,
                         ttl: float | None = None) -> None:
        """Add a runtime transform for `host` (the re-seal mint seam), optionally
        expiring `ttl` seconds from now. ttl=None means it never expires."""
        expires_at = (self._clock() + ttl) if ttl is not None else None
        self._runtime.setdefault(host, []).append((transform, expires_at))

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

    def __init__(self, creds: "BindingCredentials", generate_placeholder):
        self._creds = creds
        self._generate = generate_placeholder

    def mint(self, value: str, ttl: float | None, api_hosts, header: str = "Authorization") -> str:
        if not api_hosts:
            raise ValueError("mint requires at least one api_host (binding param 'api_hosts')")
        placeholder = self._generate()
        transform = Transform(
            name=f"reseal:{placeholder[:16]}",
            scheme=schemes.SCHEMES["bearer"],
            params={"header": header},
            placeholder=placeholder,
            secrets={"value": value},
        )
        for host in api_hosts:
            self._creds.register_runtime(host, transform, ttl=ttl)
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
        # Param values are strings (e.g. `header`) or arrays of strings (e.g. a
        # re-seal scheme's `api_hosts`). A wrong type would silently break
        # injection at request time, so reject it here.
        for pk, pv in params.items():
            if isinstance(pv, str):
                continue
            if isinstance(pv, list) and all(isinstance(x, str) and x for x in pv):
                continue
            _fail(f"{source}: {where}.params['{pk}'] must be a string or array of strings")

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
        loc = schemes.location_key(scheme, params)
        for host in binding_hosts:
            group = loc_seen.setdefault((host, loc), {"unconditional": None, "by_ph": {}})
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
                if placeholder in group["by_ph"]:
                    _fail(
                        f"{source}: bindings '{group['by_ph'][placeholder]}' and "
                        f"'{name}' both write {loc[0]} on host '{host}' with the "
                        f"same placeholder '{placeholder}'"
                    )
                group["by_ph"][placeholder] = name

        transform = Transform(
            name=name,
            scheme=scheme,
            params=params,
            placeholder=placeholder,
            secrets=dict(secret),
        )
        for host in binding_hosts:
            if hostmatch.is_pattern(host):
                patterns.append((host, hostmatch.compile_pattern(host), transform))
            else:
                hosts.setdefault(host, []).append(transform)

        # Re-seal: a scheme may need extra hosts TLS-terminated (the API hosts
        # where a minted token is later used) even though no static transform
        # writes there -- the runtime layer fills in once a token is minted.
        extra = getattr(scheme, "extra_intercept_hosts", None)
        if extra is not None:
            for h in extra(params):
                if not isinstance(h, str) or not h:
                    _fail(f"{source}: {where} scheme '{scheme_name}' returned an "
                          f"invalid extra-intercept host {h!r}")
                hosts.setdefault(h, [])

        inward.append(InwardBinding(
            name=name,
            placeholder=placeholder,
            env=env,
            scheme=scheme_name,
            params=params,
            hosts=list(binding_hosts),
        ))

    return BindingCredentials(hosts, inward, patterns)
