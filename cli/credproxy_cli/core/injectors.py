"""Injector registry + placeholder generation.

An *injector* defines HOW a credential is shaped into a request for a service:
which typed scheme the proxy runs, the scheme's params, and the shape of the
inert placeholder the workspace holds. Unlike providers (executables),
injectors are declarative TOML files -- passive, reusable, drop-in.

Discovery (first match wins, user shadows bundled):
  1. $XDG_CONFIG_HOME/credproxy/injectors/<name>.toml
  2. bundled  cli/credproxy_cli/bundled/injectors/<name>.toml

Schema:
    scheme = "bearer"             # required: a scheme in core/schemes.CATALOG
    env    = "GITHUB_TOKEN"       # optional: suggested workspace env var

    [params]                      # optional; scheme-specific (defaults merged)
    header = "Authorization"      #   e.g. bearer/basic: the header to write

    [placeholder]                 # optional; pattern for the inert sentinel
    prefix  = "ghp_"
    length  = 40                  # total length including prefix
    charset = "alnumeric"         # alnumeric | hex | base64url
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from pathlib import Path

from .errors import InjectorError
from .paths import bundled_injectors_dir, injectors_config_dir
from .schemes import SchemeSpec, build_script_spec, get_scheme, merge_params

import tomllib

# Default placeholder pattern when [placeholder] is omitted.
DEFAULT_PREFIX = "credproxy_"
DEFAULT_LENGTH = 40
DEFAULT_CHARSET = "alnumeric"

_CHARSETS = {
    # Lowercase + uppercase + digits. Named "alnumeric" to match the schema
    # vocabulary; this is the safe, widely-format-valid default.
    "alnumeric": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
}


@dataclass(frozen=True)
class Placeholder:
    prefix: str
    length: int
    charset: str

    def generate(self) -> str:
        """Generate one format-valid sentinel: `prefix` followed by random
        chars from `charset` to reach `length`, via `secrets`."""
        alphabet = _CHARSETS[self.charset]
        n = self.length - len(self.prefix)
        body = "".join(secrets.choice(alphabet) for _ in range(n))
        return self.prefix + body


@dataclass(frozen=True)
class Injector:
    """A resolved injector definition: the typed scheme the proxy runs, its
    params (merged with the scheme's defaults), the suggested env var, and the
    placeholder pattern the workspace holds.

    `scheme` is the wire dispatch key -- a built-in scheme name (bearer/basic/
    body/sigv4) or "script" for a scripted injector. `spec` is the resolved
    SchemeSpec (family/slots/wire-location): from CATALOG for a built-in, or
    declared in the TOML for a scripted injector. `script` is the `.star` file
    name when scheme == "script" (its source is read+pushed at wire time).
    `params` is passed to the proxy verbatim (e.g. bearer/basic's `header`)."""

    name: str
    scheme: str
    spec: SchemeSpec
    params: dict
    env: str | None
    placeholder: Placeholder
    source: str  # "user" or "bundled"
    script: str | None = None
    # Primitive-API version a scripted injector targets (declared in the
    # manifest, pushed on the wire, validated by the proxy). 1 for built-ins.
    api: int = 1


def _placeholder_from(raw: dict, name: str) -> Placeholder:
    p = raw.get("placeholder")
    if p is None:
        return Placeholder(DEFAULT_PREFIX, DEFAULT_LENGTH, DEFAULT_CHARSET)
    if not isinstance(p, dict):
        raise InjectorError(f"injector '{name}': [placeholder] must be a table")
    prefix = p.get("prefix", DEFAULT_PREFIX)
    length = p.get("length", DEFAULT_LENGTH)
    charset = p.get("charset", DEFAULT_CHARSET)
    if not isinstance(prefix, str):
        raise InjectorError(f"injector '{name}': placeholder.prefix must be a string")
    if not isinstance(length, int) or isinstance(length, bool):
        raise InjectorError(f"injector '{name}': placeholder.length must be an integer")
    if charset not in _CHARSETS:
        raise InjectorError(
            f"injector '{name}': placeholder.charset must be one of "
            f"{', '.join(sorted(_CHARSETS))} (got {charset!r})"
        )
    if length <= len(prefix):
        raise InjectorError(
            f"injector '{name}': placeholder.length ({length}) must exceed "
            f"the prefix length ({len(prefix)})"
        )
    return Placeholder(prefix, length, charset)


def _parse(path: Path, name: str, source: str) -> Injector:
    try:
        raw = tomllib.loads(path.read_text())
    except Exception as e:
        raise InjectorError(f"injector '{name}' ({path}): TOML parse error: {e}")
    if not isinstance(raw, dict):
        raise InjectorError(f"injector '{name}': top level must be a table")

    scheme_name = raw.get("scheme")
    if not isinstance(scheme_name, str) or not scheme_name:
        raise InjectorError(
            f"injector '{name}': `scheme` is required and must be a non-empty string"
        )

    # A scripted injector (scheme = "script") declares its own family/slots/
    # location (the CLI can't run Starlark) and names a .star file; built-in
    # schemes get their spec from CATALOG.
    script = None
    api = 1
    if scheme_name == "script":
        script = raw.get("script")
        if not isinstance(script, str) or not script:
            raise InjectorError(
                f"injector '{name}': a scripted injector needs `script` "
                f"(the .star file name)"
            )
        api = raw.get("api", 1)
        if not isinstance(api, int) or isinstance(api, bool):
            raise InjectorError(f"injector '{name}': `api` must be an integer")
        location_kind = raw.get("location_kind", "header")
        spec = build_script_spec(
            family=raw.get("family"),
            slots=raw.get("slots"),
            location_kind=location_kind,
            header_default="Authorization" if location_kind == "header" else None,
            where=f"injector '{name}'",
        )
    else:
        spec = get_scheme(scheme_name)  # raises InjectorError on an unknown scheme

    params_raw = raw.get("params")
    if params_raw is not None and not isinstance(params_raw, dict):
        raise InjectorError(f"injector '{name}': [params] must be a table")
    params = merge_params(spec, params_raw)
    # Param values must be strings (current schemes use only string params,
    # e.g. `header`); a non-string would silently break injection downstream.
    for pk, pv in params.items():
        if not isinstance(pv, str):
            raise InjectorError(
                f"injector '{name}': params['{pk}'] must be a string"
            )

    env = raw.get("env")
    if env is not None and (not isinstance(env, str) or not env):
        raise InjectorError(f"injector '{name}': `env` must be a non-empty string")

    return Injector(
        name=name,
        scheme=scheme_name,
        spec=spec,
        script=script,
        api=api,
        params=params,
        env=env,
        placeholder=_placeholder_from(raw, name),
        source=source,
    )


def find_injector(name: str) -> Injector:
    """Resolve an injector by name; user registry shadows bundled."""
    for source, base in (("user", injectors_config_dir()),
                         ("bundled", bundled_injectors_dir())):
        path = base / f"{name}.toml"
        if path.is_file():
            return _parse(path, name, source)
    raise InjectorError(
        f"injector '{name}' not found (looked for {name}.toml in "
        f"{injectors_config_dir()} and {bundled_injectors_dir()})"
    )


def list_injectors() -> list[Injector]:
    """All resolvable injectors, user shadowing bundled, sorted by name."""
    seen: dict[str, Injector] = {}
    for source, base in (("bundled", bundled_injectors_dir()),
                         ("user", injectors_config_dir())):
        if not base.is_dir():
            continue
        for path in base.iterdir():
            if path.suffix == ".toml" and path.is_file():
                name = path.stem
                seen[name] = _parse(path, name, source)
    return [seen[n] for n in sorted(seen)]
