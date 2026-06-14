"""Proxy configuration: intercept set + per-host injection transforms.

The proxy receives an already-resolved config (literal secret values, no
template references) via POST /admin/config. The host CLI is the supported
producer; it resolves each binding's secret from its provider before posting.

This module validates the parsed dict and produces a BindingCredentials
instance. Wire schema (design-v3, scheme-aware):

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

Credentials API:
  - `intercept_hosts()`  -> set[str]: union of all bindings' hosts.
  - `transforms_for(host)` -> list[Transform]: transforms active for a host,
    static (pushed) layer plus a runtime-augmentable layer (the re-seal seam;
    empty today).
  - `inward_bindings()`  -> list[InwardBinding]: least-disclosure descriptors
    for /setup (no secret values, no provider/secret-id).
"""
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

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
    def intercept_hosts(self) -> set[str]: ...
    def transforms_for(self, host: str) -> list[Transform]: ...
    def inward_bindings(self) -> list[InwardBinding]: ...


class BindingCredentials:
    """Credentials built from the bindings wire format.

    The host->transforms map is the *static* layer pushed via /admin/config.
    `transforms_for` overlays a *runtime* layer (re-seal seam, design-v3): the
    substitution set must be a function over (static + runtime-augmentable),
    never baked immutable at push time, so dynamically-minted placeholders can
    be registered later. The runtime layer is empty until re-seal lands.
    """

    def __init__(
        self,
        hosts: dict[str, list[Transform]],
        bindings: list[InwardBinding] | None = None,
    ):
        self._hosts = hosts
        self._runtime: dict[str, list[Transform]] = {}
        self._bindings: list[InwardBinding] = bindings or []

    def intercept_hosts(self) -> set[str]:
        return set(self._hosts) | set(self._runtime)

    def transforms_for(self, host: str) -> list[Transform]:
        return list(self._hosts.get(host, [])) + list(self._runtime.get(host, []))

    def register_runtime(self, host: str, transform: Transform) -> None:
        """Add a runtime transform (re-seal seam; unused today)."""
        self._runtime.setdefault(host, []).append(transform)

    def inward_bindings(self) -> list[InwardBinding]:
        return list(self._bindings)


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
    loc_seen: dict[tuple, str] = {}  # (host, location) -> binding name
    hosts: dict[str, list[Transform]] = {}
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

        # --- hosts ---
        binding_hosts = entry.get("hosts")
        if not isinstance(binding_hosts, list) or not binding_hosts \
                or not all(isinstance(h, str) and h for h in binding_hosts):
            _fail(f"{source}: {where}.hosts must be a non-empty array of strings")

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
        # Param values must be strings (current schemes use only string params,
        # e.g. `header`). A non-string would silently break injection at request
        # time; relax this if a scheme ever needs structured params.
        for pk, pv in params.items():
            if not isinstance(pv, str):
                _fail(f"{source}: {where}.params['{pk}'] must be a string")

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

        # --- (host, location) uniqueness ---
        loc = schemes.location_key(scheme, params)
        for host in binding_hosts:
            key = (host, loc)
            if key in loc_seen:
                _fail(
                    f"{source}: bindings '{loc_seen[key]}' and '{name}' both "
                    f"write {loc[0]} on host '{host}'"
                )
            loc_seen[key] = name

        transform = Transform(
            name=name,
            scheme=scheme,
            params=params,
            placeholder=placeholder,
            secrets=dict(secret),
        )
        for host in binding_hosts:
            hosts.setdefault(host, []).append(transform)

        inward.append(InwardBinding(
            name=name,
            placeholder=placeholder,
            env=env,
            scheme=scheme_name,
            params=params,
            hosts=list(binding_hosts),
        ))

    return BindingCredentials(hosts, inward)
