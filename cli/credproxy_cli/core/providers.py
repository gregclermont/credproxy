"""Provider registry + invocation.

A *provider* is a host-side executable that fetches secret values from a
backend, speaking the small versioned stdin/stdout protocol documented in
`docs/providers.md`. This module resolves a provider by name and execs it,
mapping its exit codes to typed errors. The CLI pushes the *resolved* values
to the proxy; the protocol deliberately says nothing about who the parent is
(today the CLI, tomorrow maybe a daemon).

The protocol is **batch-native** (design-v3): one invocation carries a list of
refs and returns a ref->value map. This means a binding's whole multi-slot
credential resolves in a single exec -- an interactive provider prompts once,
a vault provider can coalesce same-item refs. A single value is just a list of
one; there is no single/batch duality on the wire.

Discovery (first match wins, user shadows bundled):
  1. $XDG_CONFIG_HOME/credproxy/providers/<name>
  2. bundled  cli/credproxy_cli/bundled/providers/<name>
Each location is either an executable file, or a directory holding an
executable `run`.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import ProviderError
from .paths import bundled_providers_dir, providers_config_dir

PROTOCOL_VERSION = 1

# Generous: a provider may wrap an interactive vault CLI that prompts on the
# (inherited) terminal for a passphrase or MFA tap.
FETCH_TIMEOUT = 120.0

# Exit-code meanings from the provider protocol (docs/providers.md).
EXIT_NOT_FOUND = 2
EXIT_UNSUPPORTED = 3


@dataclass(frozen=True)
class Provider:
    """A resolved provider: its name and the executable to run."""

    name: str
    exe: Path
    source: str  # "user" or "bundled" -- for diagnostics / `list`


def _resolve_in(dir_: Path, name: str) -> Path | None:
    """Return the executable for `name` under `dir_`, or None.

    `dir_/name` may be an executable file, or a directory holding an
    executable `run`."""
    cand = dir_ / name
    if cand.is_file() and os.access(cand, os.X_OK):
        return cand
    run = cand / "run"
    if cand.is_dir() and run.is_file() and os.access(run, os.X_OK):
        return run
    return None


def find_provider(name: str) -> Provider:
    """Resolve a provider by name; user registry shadows bundled.

    Raises ProviderError if no executable provider is found (covers the
    case where a file exists but is not executable, with a hint)."""
    for source, base in (("user", providers_config_dir()),
                         ("bundled", bundled_providers_dir())):
        exe = _resolve_in(base, name)
        if exe is not None:
            return Provider(name=name, exe=exe, source=source)
    # A clearer message if something is present but not runnable.
    for base in (providers_config_dir(), bundled_providers_dir()):
        if (base / name).exists():
            raise ProviderError(
                f"provider '{name}' found at {base / name} but is not an "
                f"executable file or a directory with an executable `run`"
            )
    raise ProviderError(
        f"provider '{name}' not found (looked in {providers_config_dir()} "
        f"and {bundled_providers_dir()})"
    )


def list_providers() -> list[Provider]:
    """All resolvable providers, user shadowing bundled, sorted by name."""
    seen: dict[str, Provider] = {}
    for source, base in (("bundled", bundled_providers_dir()),
                         ("user", providers_config_dir())):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            exe = _resolve_in(base, entry.name)
            if exe is not None:
                seen[entry.name] = Provider(entry.name, exe, source)
    return [seen[n] for n in sorted(seen)]


def _tail(text: str, lines: int = 5) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def fetch_many(provider_name: str, refs: list[str]) -> dict[str, str]:
    """Exec the named provider once with a batch `get` request and return the
    ref->value map.

    stdin carries the request JSON (`{"version":1,"op":"get","secrets":[...]}`);
    stdout must be exactly the response JSON (`{"values":{ref:value,...}}`);
    stderr stays inherited from the terminal so interactive providers can
    prompt. Exit codes map to ProviderError variants (2 = not found,
    3 = unsupported, other nonzero = generic failure). Every requested ref
    must appear in `values` as a string, or it is a protocol error."""
    if not refs:
        return {}
    provider = find_provider(provider_name)
    refs_label = ", ".join(f"'{r}'" for r in refs)
    request = json.dumps(
        {"version": PROTOCOL_VERSION, "op": "get", "secrets": list(refs)}
    )

    try:
        # stderr is NOT captured: it is inherited from the terminal so an
        # interactive provider can prompt. We therefore have no stderr tail
        # to quote on failure -- diagnostics the user already saw.
        proc = subprocess.run(
            [str(provider.exe)],
            input=request,
            stdout=subprocess.PIPE,
            text=True,
            timeout=FETCH_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ProviderError(
            f"provider '{provider_name}' timed out after "
            f"{FETCH_TIMEOUT:.0f}s fetching {refs_label}"
        )
    except OSError as e:
        raise ProviderError(
            f"provider '{provider_name}' ({provider.exe}) failed to "
            f"execute: {e}"
        )

    if proc.returncode == EXIT_NOT_FOUND:
        raise ProviderError(
            f"provider '{provider_name}': secret(s) {refs_label} not found"
        )
    if proc.returncode == EXIT_UNSUPPORTED:
        raise ProviderError(
            f"provider '{provider_name}' does not support this request "
            f"(version {PROTOCOL_VERSION}, op 'get')"
        )
    if proc.returncode != 0:
        raise ProviderError(
            f"provider '{provider_name}' failed (exit {proc.returncode}) "
            f"fetching {refs_label}"
        )

    out = proc.stdout or ""
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        raise ProviderError(
            f"provider '{provider_name}' returned non-JSON on stdout: "
            f"{_tail(out)!r}"
        )
    if not isinstance(payload, dict) or not isinstance(payload.get("values"), dict):
        raise ProviderError(
            f"provider '{provider_name}' response is missing a `values` object"
        )
    values = payload["values"]
    resolved: dict[str, str] = {}
    for ref in refs:
        if ref not in values:
            raise ProviderError(
                f"provider '{provider_name}' response is missing ref '{ref}'"
            )
        v = values[ref]
        if not isinstance(v, str):
            raise ProviderError(
                f"provider '{provider_name}': value for '{ref}' must be a "
                f"string, got {type(v).__name__}"
            )
        resolved[ref] = v
    return resolved


def fetch(provider_name: str, secret_id: str) -> str:
    """Resolve a single ref. Convenience wrapper over the batch protocol."""
    return fetch_many(provider_name, [secret_id])[secret_id]
