"""Proxy configuration: intercept set + per-host placeholder substitution.

Two ways to feed the proxy:

1. **YAML on disk** (the original path): a bind-mounted file with
   `${secret:NAME}` references resolved at startup against secrets
   passed in via the stdin envelope. `config.load(secrets, path)`.

2. **Resolved JSON via /admin/config** (host CLI path): values are
   already-resolved literal strings; no `${secret:NAME}` refs allowed.
   `config.load_resolved(parsed_dict)`.

Both paths produce a YamlCredentials. Callers go through the
Credentials interface, never the file directly — so a future
host-plugin IPC implementation can swap in without touching the inject
path.

Schema (same for both paths):

    hosts:
      api.github.com:
        headers:
          Authorization:
            placeholder: "credproxy_github_test"   # what workspace sends
            real: "..."                             # what proxy substitutes

A host listed under `hosts:` is intercepted (TLS terminated). `headers:`
may be omitted or empty — intercept and log, no substitution.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

CONFIG_PATH = Path("/opt/proxy/config.yaml")
SECRET_REF = re.compile(r"\$\{secret:([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class Substitution:
    header: str
    placeholder: str
    real: str


class Credentials(Protocol):
    def intercept_hosts(self) -> set[str]: ...
    def substitutions_for(self, host: str) -> list[Substitution]: ...
    def workspace_tokens(self) -> dict[str, dict[str, str]]: ...


class YamlCredentials:
    def __init__(self, hosts: dict[str, list[Substitution]]):
        self._hosts = hosts

    def intercept_hosts(self) -> set[str]:
        return set(self._hosts)

    def substitutions_for(self, host: str) -> list[Substitution]:
        return list(self._hosts.get(host, []))

    def workspace_tokens(self) -> dict[str, dict[str, str]]:
        return {
            host: {sub.header: sub.placeholder for sub in subs}
            for host, subs in self._hosts.items()
        }


class ConfigError(Exception):
    """Raised on validation/parse failure. Callers decide how to handle:
    the startup path SystemExits; the admin endpoint returns 400."""


def _fail(msg: str) -> None:
    raise ConfigError(f"[config] {msg}")


def _resolve_secrets(value: str, secrets: dict[str, str], where: str) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in secrets:
            _fail(
                f"{where} references ${{secret:{name}}} but {name} was not "
                f"provided"
            )
        return secrets[name]
    return SECRET_REF.sub(sub, value)


def load(secrets: dict[str, str], path: Path = CONFIG_PATH) -> YamlCredentials:
    """Load YAML from `path`, resolve `${secret:NAME}` against `secrets`."""
    if not path.exists():
        _fail(f"missing config file: {path}")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        _fail(f"malformed YAML in {path}: {e}")
    return _build(raw, secrets, source=str(path))


def load_resolved(raw: Any, source: str = "<resolved>") -> YamlCredentials:
    """Build credentials from an already-resolved dict (no ${secret:NAME}).

    Caller is responsible for any secret resolution before invoking. If
    the input still contains `${secret:NAME}` references, validation
    fails because the resolver is given an empty secrets dict.
    """
    return _build(raw, secrets={}, source=source)


def _build(
    raw: Any, secrets: dict[str, str], source: str
) -> YamlCredentials:
    if not isinstance(raw, dict) or "hosts" not in raw:
        _fail(f"{source}: missing top-level `hosts:` key")
    hosts_raw = raw["hosts"] or {}
    if not isinstance(hosts_raw, dict):
        _fail(f"{source}: `hosts:` must be a mapping")

    hosts: dict[str, list[Substitution]] = {}
    for host, entry in hosts_raw.items():
        entry = entry or {}
        if not isinstance(entry, dict):
            _fail(f"{source}: hosts.{host} must be a mapping")
        headers = entry.get("headers") or {}
        if not isinstance(headers, dict):
            _fail(f"{source}: hosts.{host}.headers must be a mapping")

        subs: list[Substitution] = []
        for header, hentry in headers.items():
            if not isinstance(hentry, dict):
                _fail(
                    f"{source}: hosts.{host}.headers.{header} must be a mapping "
                    f"with `placeholder` and `real`"
                )
            placeholder = hentry.get("placeholder")
            real = hentry.get("real")
            if not isinstance(placeholder, str) or not placeholder:
                _fail(
                    f"{source}: hosts.{host}.headers.{header}.placeholder "
                    f"must be a non-empty string"
                )
            if not isinstance(real, str) or not real:
                _fail(
                    f"{source}: hosts.{host}.headers.{header}.real "
                    f"must be a non-empty string"
                )
            real = _resolve_secrets(
                real, secrets, f"{source}: hosts.{host}.headers.{header}.real"
            )
            subs.append(Substitution(header=header, placeholder=placeholder, real=real))
        hosts[host] = subs
    return YamlCredentials(hosts)
