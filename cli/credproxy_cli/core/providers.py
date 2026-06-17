"""Provider registry + invocation.

A *provider* is a host-side executable that fetches secret values from a
backend, speaking the small versioned stdin/stdout protocol documented in
`docs/providers.md`. This module resolves a provider by name and execs it,
mapping its exit codes to typed errors. The CLI pushes the *resolved* values
to the proxy; the protocol deliberately says nothing about who the parent is
(today the CLI, tomorrow maybe a daemon).

The protocol is **batch-native**: one invocation carries a list of
refs and returns a ref->value map. This means a binding's whole multi-slot
credential resolves in a single exec -- an interactive provider prompts once,
a vault provider can coalesce same-item refs. A single value is just a list of
one; there is no single/batch duality on the wire.

Discovery (first match wins, user shadows profile shadows builtin):
  1. user     $XDG_CONFIG_HOME/credproxy/providers/<name>
  2. profile  <$CREDPROXY_PROFILE_DIR or repo/profile>/providers/<name>
  3. builtin  cli/credproxy_cli/builtin/providers/<name>
Each location is either an executable file, or a directory holding an
executable `run`.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import ProviderError
from .paths import layered_dirs

PROTOCOL_VERSION = 1

# Generous: a provider may wrap an interactive vault CLI that prompts on the
# (inherited) terminal for a passphrase or MFA tap.
FETCH_TIMEOUT = 120.0

# Exit-code meanings from the provider protocol (docs/providers.md).
EXIT_NOT_FOUND = 2
EXIT_UNSUPPORTED = 3


@contextlib.contextmanager
def _preserve_tty():
    """Snapshot and restore the controlling terminal around a provider exec.

    An interactive provider (e.g. `bw`/`op` prompting for a master password via
    getpass) puts /dev/tty into no-echo through termios and restores it in its
    own `finally`. But if FETCH_TIMEOUT fires while it blocks on input,
    subprocess kills it with SIGKILL -- its restore never runs, and the user's
    shell is left with echo off (typed input invisible). The parent owns the
    subprocess lifecycle, so it is the only place that can guarantee cleanup: we
    snapshot the tty before the exec and restore it unconditionally after, so a
    killed or crashed provider can't corrupt the terminal.

    No controlling terminal (CI, piped) or no termios (non-Unix host) -> a
    harmless no-op. TCSAFLUSH on restore discards anything the user typed blind
    during the hang (e.g. a half-entered password), keeping it out of the shell.
    """
    try:
        import termios
    except ImportError:
        termios = None
    fd, saved = -1, None
    if termios is not None:
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            saved = termios.tcgetattr(fd)
        except Exception:
            saved = None  # no usable tty -> nothing to protect
    try:
        yield
    finally:
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
            except Exception:
                pass  # restore is best-effort; never mask the real error
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True)
class Provider:
    """A resolved provider: its name and the executable to run."""

    name: str
    exe: Path
    source: str  # "user" or "builtin" -- for diagnostics / `list`
    description: str | None = None  # from the `describe` op, for `list`


def _ask(exe: Path, op: str, field: str) -> str | None:
    """Exec a provider with a metadata op (`describe`/`help`) and read back the
    named string field. Best-effort -- any failure (a provider that doesn't
    implement the op and exits non-zero, non-JSON output, a timeout, an error)
    yields None. This RUNS the provider, so it backs `list`/`show` only, never
    the fetch hot path."""
    req = json.dumps({"version": PROTOCOL_VERSION, "op": op})
    try:
        # _preserve_tty for the same reason as the fetch path: a provider that
        # touches /dev/tty and is then killed by this timeout must not leave the
        # terminal in no-echo (well-behaved metadata ops don't prompt, but a
        # third-party provider might).
        with _preserve_tty():
            proc = subprocess.run(
                [str(exe)], input=req,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=5,
            )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        return None
    val = payload.get(field) if isinstance(payload, dict) else None
    return val if isinstance(val, str) and val else None


def _describe(exe: Path) -> str | None:
    """One-line description (the `describe` op), for `provider list`."""
    return _ask(exe, "describe", "description")


def _help(exe: Path) -> str | None:
    """Longer-form usage help (the `help` op), for `provider show`."""
    return _ask(exe, "help", "help")


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
    """Resolve a provider by name; user registry shadows builtin.

    Raises ProviderError if no executable provider is found (covers the
    case where a file exists but is not executable, with a hint)."""
    searched = layered_dirs("providers")
    for source, base in searched:
        exe = _resolve_in(base, name)
        if exe is not None:
            return Provider(name=name, exe=exe, source=source)
    # A clearer message if something is present but not runnable.
    for _, base in searched:
        if (base / name).exists():
            raise ProviderError(
                f"provider '{name}' found at {base / name} but is not an "
                f"executable file or a directory with an executable `run`"
            )
    where = ", ".join(str(b) for _, b in searched)
    raise ProviderError(f"provider '{name}' not found (looked in {where})")


def list_providers() -> list[Provider]:
    """All resolvable providers, user shadowing builtin, sorted by name."""
    seen: dict[str, Provider] = {}
    for source, base in reversed(layered_dirs("providers")):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            exe = _resolve_in(base, entry.name)
            if exe is not None:
                seen[entry.name] = Provider(
                    entry.name, exe, source, _describe(exe))
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
        # to quote on failure -- diagnostics the user already saw. _preserve_tty
        # guards against a provider that disables echo to prompt and is then
        # killed by the timeout before restoring it (would leave the shell
        # with input echo off).
        with _preserve_tty():
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
