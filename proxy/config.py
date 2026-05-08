"""Proxy configuration: intercept set + per-host placeholder substitution.

The proxy receives an already-resolved config (literal `real:` values,
no template references) via POST /admin/config. The host CLI
`bin/credproxy push-config` is the supported producer; it reads a YAML
config and resolves `${secret:NAME}` references against host
environment variables before posting.

This module validates the parsed dict and produces a Credentials
instance. Schema:

    hosts:
      api.github.com:
        headers:
          Authorization:
            placeholder: "credproxy_test"   # what workspace sends
            real: "<literal value>"          # what proxy substitutes

A host listed under `hosts:` is intercepted (TLS terminated). `headers:`
may be omitted or empty — intercept and log, no substitution.
"""
import re
from dataclasses import dataclass
from typing import Any, Protocol

_SECRET_REF = re.compile(r"\$\{secret:([A-Za-z_][A-Za-z0-9_]*)\}")


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
    """Raised on validation failure. Callers decide how to handle:
    main.py SystemExits at startup; the admin endpoint returns 400."""


def _fail(msg: str) -> None:
    raise ConfigError(f"[config] {msg}")


def load_resolved(raw: Any, source: str = "<resolved>") -> YamlCredentials:
    """Build credentials from a parsed dict (already-resolved values).

    `raw` should be the deserialized form of the schema documented at
    the top of this module. Any remaining `${...}` template-looking
    text is left as-is — substitution is the caller's responsibility.
    """
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
            unresolved = _SECRET_REF.search(real)
            if unresolved:
                _fail(
                    f"{source}: hosts.{host}.headers.{header}.real contains "
                    f"unresolved ${{secret:{unresolved.group(1)}}} -- "
                    f"the caller is expected to resolve before posting"
                )
            subs.append(Substitution(header=header, placeholder=placeholder, real=real))
        hosts[host] = subs
    return YamlCredentials(hosts)
