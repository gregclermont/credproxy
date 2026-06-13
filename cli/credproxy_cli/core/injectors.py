"""Injector registry + placeholder generation.

An *injector* defines HOW a credential is shaped into a request for a service:
which header it rides in, how it is formatted, and the shape of the inert
placeholder the workspace holds. Unlike providers (executables), injectors are
declarative TOML files -- passive, reusable, drop-in.

Discovery (first match wins, user shadows bundled):
  1. $XDG_CONFIG_HOME/credproxy/injectors/<name>.toml
  2. bundled  cli/credproxy_cli/bundled/injectors/<name>.toml

Schema:
    header = "Authorization"      # required: header carrying the credential
    format = "Bearer {value}"     # optional, default "{value}"
    env    = "GITHUB_TOKEN"       # optional: suggested workspace env var

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

import tomllib

# Default placeholder pattern when [placeholder] is omitted.
DEFAULT_PREFIX = "credproxy_"
DEFAULT_LENGTH = 40
DEFAULT_CHARSET = "alnumeric"

# `format` default: the credential value verbatim.
DEFAULT_FORMAT = "{value}"

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
    """A resolved injector definition.

    NOTE on `format`: the proxy's substitution is a literal substring replace
    of placeholder -> real value INSIDE whatever header value the client sent.
    The injector's `format` describes what the WORKSPACE is expected to send
    (and so what the placeholder is embedded in) -- it informs the env-var
    suggestion and authoring docs, NOT the wire config, which today only needs
    the bare placeholder -> real mapping. `format` is kept in the schema because
    the authoring contract evolves in a later wave (the proxy may apply the
    full format itself); for now treat it as documentation."""

    name: str
    header: str
    format: str
    env: str | None
    placeholder: Placeholder
    source: str  # "user" or "bundled"


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

    header = raw.get("header")
    if not isinstance(header, str) or not header:
        raise InjectorError(
            f"injector '{name}': `header` is required and must be a non-empty string"
        )
    fmt = raw.get("format", DEFAULT_FORMAT)
    if not isinstance(fmt, str) or "{value}" not in fmt:
        raise InjectorError(
            f"injector '{name}': `format` must be a string containing '{{value}}'"
        )
    env = raw.get("env")
    if env is not None and (not isinstance(env, str) or not env):
        raise InjectorError(f"injector '{name}': `env` must be a non-empty string")

    return Injector(
        name=name,
        header=header,
        format=fmt,
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
