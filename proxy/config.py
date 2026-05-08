"""Proxy configuration: intercept set + per-host placeholder substitution.

The on-disk format is a single YAML file (CONFIG_PATH). Callers go
through the Credentials interface, never the file directly — so a future
host-plugin IPC implementation can swap in without touching the inject
path.

Schema:

    hosts:
      api.github.com:
        headers:
          Authorization:
            placeholder: "credproxy_github_test"   # what workspace sends
            real: "${secret:GITHUB_PAT}"            # resolved from stdin

`real:` may be a literal string or contain `${secret:NAME}` references
that are resolved at startup against secrets passed on stdin (see
main._load_secrets). Missing references fail loudly. Secrets never
touch disk or the process environment.

The proxy publishes the placeholder via the /tokens bootstrap endpoint;
the workspace uses it like a real token. On intercepted flows, the
proxy substring-replaces placeholder -> real in the named header before
forwarding upstream.

A host listed under `hosts:` is intercepted (TLS terminated). `headers:`
may be omitted or empty — intercept and log, no substitution.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

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


def _fail(msg: str) -> None:
    raise SystemExit(f"[config] {msg}")


def _resolve_secrets(value: str, secrets: dict[str, str], where: str) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in secrets:
            _fail(
                f"{where} references ${{secret:{name}}} but {name} was not "
                f"provided on stdin"
            )
        return secrets[name]
    return SECRET_REF.sub(sub, value)


def load(secrets: dict[str, str], path: Path = CONFIG_PATH) -> YamlCredentials:
    if not path.exists():
        _fail(f"missing config file: {path}")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        _fail(f"malformed YAML in {path}: {e}")

    if not isinstance(raw, dict) or "hosts" not in raw:
        _fail(f"{path}: missing top-level `hosts:` key")
    hosts_raw = raw["hosts"] or {}
    if not isinstance(hosts_raw, dict):
        _fail(f"{path}: `hosts:` must be a mapping")

    hosts: dict[str, list[Substitution]] = {}
    for host, entry in hosts_raw.items():
        entry = entry or {}
        if not isinstance(entry, dict):
            _fail(f"{path}: hosts.{host} must be a mapping")
        headers = entry.get("headers") or {}
        if not isinstance(headers, dict):
            _fail(f"{path}: hosts.{host}.headers must be a mapping")

        subs: list[Substitution] = []
        for header, hentry in headers.items():
            if not isinstance(hentry, dict):
                _fail(
                    f"{path}: hosts.{host}.headers.{header} must be a mapping "
                    f"with `placeholder` and `real`"
                )
            placeholder = hentry.get("placeholder")
            real = hentry.get("real")
            if not isinstance(placeholder, str) or not placeholder:
                _fail(
                    f"{path}: hosts.{host}.headers.{header}.placeholder "
                    f"must be a non-empty string"
                )
            if not isinstance(real, str) or not real:
                _fail(
                    f"{path}: hosts.{host}.headers.{header}.real "
                    f"must be a non-empty string"
                )
            real = _resolve_secrets(
                real, secrets, f"{path}: hosts.{host}.headers.{header}.real"
            )
            subs.append(Substitution(header=header, placeholder=placeholder, real=real))
        hosts[host] = subs
    return YamlCredentials(hosts)
