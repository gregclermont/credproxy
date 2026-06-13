"""Bindings: the workspace-owned ties between an injector, a provider, and a
host scope, plus their on-disk materialization and the proxy wire mapping.

A binding connects:
  name . injector . provider . secret-id . placeholder . hostname scope

It lives as a `[[binding]]` table in the workspace TOML. This module:
  - parses + validates the `[[binding]]` array (`load_bindings`),
  - materializes missing `name`/`placeholder` back into the file with a
    SURGICAL text edit that preserves comments and ordering
    (`materialize_bindings`),
  - appends/removes a binding block as a text edit (`append_binding`,
    `remove_binding`),
  - maps resolved bindings onto the proxy's EXISTING wire shape
    (`wire_config`), so today's unmodified proxy keeps working.

No-hidden-state principle: the TOML file is the single source of truth.
Generated names/placeholders are written back, not held in memory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .errors import ConfigError
from .injectors import Injector, find_injector
from .providers import fetch_many as provider_fetch_many
from .schemes import get_scheme, location_key
from .workspace import Workspace

import tomllib

Notify = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


@dataclass(frozen=True)
class Binding:
    name: str
    injector: str
    provider: str
    # Single-slot sugar (bare ref) or a slot->ref table for multi-slot schemes.
    secret: str | dict[str, str]
    hosts: tuple[str, ...]
    placeholder: str | None  # None until materialized
    env: str | None


def secret_refs(binding: Binding) -> dict[str, str]:
    """Normalize a binding's `secret` to a slot->ref map. A bare string is the
    single-slot `value` sugar; a table is taken verbatim."""
    if isinstance(binding.secret, str):
        return {"value": binding.secret}
    return dict(binding.secret)


def secret_display(secret: str | dict[str, str]) -> str:
    """Human-friendly rendering of a binding's secret refs (never values)."""
    if isinstance(secret, str):
        return secret
    return ", ".join(f"{slot}={ref}" for slot, ref in secret.items())


# ---- parsing / validation ---------------------------------------------------


def _parse_bindings(raw: dict, source: str) -> list[Binding]:
    """Parse the `[[binding]]` array from a raw TOML dict. Validates field
    types/presence but NOT cross-binding uniqueness (see `validate`)."""
    items = raw.get("binding") or []
    if not isinstance(items, list):
        raise ConfigError(f"{source}: `binding` must be an array of tables")
    out: list[Binding] = []
    for i, b in enumerate(items):
        if not isinstance(b, dict):
            raise ConfigError(f"{source}: binding[{i}] must be a table")
        where = f"binding[{i}]"

        injector = b.get("injector")
        if not isinstance(injector, str) or not injector:
            raise ConfigError(f"{source}: {where}.injector is required (string)")
        provider = b.get("provider")
        if not isinstance(provider, str) or not provider:
            raise ConfigError(f"{source}: {where}.provider is required (string)")
        secret = b.get("secret")
        if isinstance(secret, str):
            if not secret:
                raise ConfigError(f"{source}: {where}.secret must be non-empty")
        elif isinstance(secret, dict):
            if not secret or not all(
                isinstance(k, str) and k and isinstance(v, str) and v
                for k, v in secret.items()
            ):
                raise ConfigError(
                    f"{source}: {where}.secret table must map non-empty slot "
                    f"names to non-empty refs"
                )
            secret = dict(secret)
        else:
            raise ConfigError(
                f"{source}: {where}.secret is required (a ref string or a "
                f"slot->ref table)"
            )

        hosts = b.get("hosts")
        if not isinstance(hosts, list) or not hosts \
                or not all(isinstance(h, str) and h for h in hosts):
            raise ConfigError(
                f"{source}: {where}.hosts is required (non-empty array of strings)"
            )

        name = b.get("name")
        if name is not None and (not isinstance(name, str) or not name):
            raise ConfigError(f"{source}: {where}.name must be a non-empty string")
        placeholder = b.get("placeholder")
        if placeholder is not None and (not isinstance(placeholder, str) or not placeholder):
            raise ConfigError(f"{source}: {where}.placeholder must be a non-empty string")
        env = b.get("env")
        if env is not None and (not isinstance(env, str) or not env):
            raise ConfigError(f"{source}: {where}.env must be a non-empty string")

        out.append(Binding(
            name=name,            # may be None -> materialized later
            injector=injector,
            provider=provider,
            secret=secret,
            hosts=tuple(hosts),
            placeholder=placeholder,  # may be None -> materialized later
            env=env,
        ))
    return out


def _auto_name(injector: str, provider: str, taken: set[str]) -> str:
    """`<injector>-<provider>`, with a numeric suffix on collision."""
    base = f"{injector}-{provider}"
    if base not in taken:
        return base
    i = 2
    while f"{base}-{i}" in taken:
        i += 1
    return f"{base}-{i}"


def validate(bindings: list[Binding], source: str) -> None:
    """Cross-binding validation: unique names; unique (host, wire-location);
    injector/provider must resolve; and the binding's secret slots must match
    the scheme's. Names must already be materialized (non-None) for the
    uniqueness check; callers run this post-materialize."""
    from .providers import find_provider

    names: set[str] = set()
    seen_loc: dict[tuple, str] = {}  # (host, location) -> binding name
    for b in bindings:
        if b.name is None:
            # Should not happen post-materialize; defensive.
            raise ConfigError(f"{source}: a binding is missing a name")
        if b.name in names:
            raise ConfigError(f"{source}: duplicate binding name '{b.name}'")
        names.add(b.name)

        # injector + provider must exist (raises InjectorError/ProviderError).
        injector = find_injector(b.injector)
        find_provider(b.provider)
        spec = get_scheme(injector.scheme)

        # secret slots must match the scheme's declared slots.
        got = set(secret_refs(b))
        want = set(spec.slots)
        if got != want:
            raise ConfigError(
                f"{source}: binding '{b.name}' scheme '{injector.scheme}' needs "
                f"secret slot(s) {{{', '.join(sorted(want))}}}, got "
                f"{{{', '.join(sorted(got))}}}"
            )

        loc = location_key(spec, injector.params)
        for host in b.hosts:
            key = (host, loc)
            if key in seen_loc:
                raise ConfigError(
                    f"{source}: bindings '{seen_loc[key]}' and '{b.name}' both "
                    f"write {loc[0]} on host '{host}'"
                )
            seen_loc[key] = b.name


def load_bindings(ws: Workspace) -> list[Binding]:
    """Parse + validate the workspace's `[[binding]]` array. Assumes names
    and placeholders are already materialized (call `materialize_bindings`
    first, as lifecycle/porcelain do). Raises ConfigError on validation
    failure."""
    raw = tomllib.loads(ws.config_path.read_text())
    source = str(ws.config_path)
    bindings = _parse_bindings(raw, source)
    # Fill auto-names in-memory for validation even if not yet on disk, so
    # validate's uniqueness check is meaningful when called standalone.
    bindings = _with_auto_names(bindings)
    validate(bindings, source)
    return bindings


def _with_auto_names(bindings: list[Binding]) -> list[Binding]:
    """Return bindings with any None name filled by the auto-name rule
    (in-memory only)."""
    taken = {b.name for b in bindings if b.name}
    out: list[Binding] = []
    for b in bindings:
        if b.name is None:
            name = _auto_name(b.injector, b.provider, taken)
            taken.add(name)
            out.append(replace(b, name=name))
        else:
            out.append(b)
    return out


# ---- materialization (surgical text edits) ----------------------------------

# A `[[binding]]` table header line.
_BLOCK_HEADER_RE = re.compile(r"^\s*\[\[\s*binding\s*\]\]\s*$")
# Start of any other top-level table/array-of-tables (ends the current block).
_TABLE_START_RE = re.compile(r"^\s*\[")


def _block_spans(text: str) -> list[tuple[int, int]]:
    """Index the `[[binding]]` blocks in `text` by line range [start, end)
    (end exclusive), where `start` is the header line and the block runs to
    the next table header or EOF. Trailing blank lines stay OUTSIDE the block
    so inserts land tightly."""
    lines = text.splitlines(keepends=True)
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(lines)
    while i < n:
        if _BLOCK_HEADER_RE.match(lines[i]):
            start = i
            j = i + 1
            while j < n and not _TABLE_START_RE.match(lines[j]):
                j += 1
            # Trim trailing blank lines from the block end.
            end = j
            while end - 1 > start and lines[end - 1].strip() == "":
                end -= 1
            spans.append((start, end))
            i = j
        else:
            i += 1
    return spans


def _insert_line_in_block(text: str, block_index: int, line: str) -> str:
    """Append `line` (no trailing newline) at the end of the block-index'th
    `[[binding]]` block, preserving everything else verbatim."""
    lines = text.splitlines(keepends=True)
    spans = _block_spans(text)
    _start, end = spans[block_index]
    # Ensure the line before insertion ends with a newline.
    if end > 0 and not lines[end - 1].endswith("\n"):
        lines[end - 1] = lines[end - 1] + "\n"
    lines.insert(end, line + "\n")
    return "".join(lines)


def materialize_bindings(ws: Workspace, notify: Notify = _noop) -> list[Binding]:
    """Ensure every binding has a static `name` and `placeholder` on disk.

    For each binding missing one, generate it (auto-name rule / the injector's
    placeholder pattern) and write the line back into THAT binding's block via
    a surgical text edit -- no whole-file re-serialization, so comments and
    ordering survive. Each materialization is announced via `notify`.

    Returns the parsed + validated bindings (with names/placeholders filled).
    Idempotent: a fully-materialized file is left byte-for-byte unchanged.
    """
    text = ws.config_path.read_text()
    raw = tomllib.loads(text)
    source = str(ws.config_path)
    bindings = _parse_bindings(raw, source)

    # Decide names first (auto-name needs the full taken-set).
    taken = {b.name for b in bindings if b.name}
    resolved: list[Binding] = []
    for b in bindings:
        name = b.name
        if name is None:
            name = _auto_name(b.injector, b.provider, taken)
            taken.add(name)
        resolved.append(replace(b, name=name))

    changed = False
    # Re-index spans after each edit since line numbers shift.
    for idx, (orig, res) in enumerate(zip(bindings, resolved)):
        if orig.name is None:
            text = _insert_line_in_block(text, idx, f'name = "{res.name}"')
            notify(f"materialized name '{res.name}' for binding [{idx}]")
            changed = True
        if orig.placeholder is None:
            injector = find_injector(res.injector)
            ph = injector.placeholder.generate()
            text = _insert_line_in_block(text, idx, f'placeholder = "{ph}"')
            resolved[idx] = replace(res, placeholder=ph)
            notify(f"materialized placeholder for binding '{res.name}'")
            changed = True

    if changed:
        ws.config_path.write_text(text)

    validate(resolved, source)
    return resolved


# ---- imperative edits -------------------------------------------------------


def append_binding(ws: Workspace, binding: Binding) -> None:
    """Append a fully-formed `[[binding]]` block to the workspace TOML as a
    text append (preserving the existing file)."""
    text = ws.config_path.read_text()
    if isinstance(binding.secret, dict):
        # Multi-slot: an inline table keeps the mapping inside the [[binding]]
        # element (a [binding.secret] sub-table is invalid under array-of-tables).
        inner = ", ".join(f'{slot} = "{ref}"' for slot, ref in binding.secret.items())
        secret_line = f"secret   = {{ {inner} }}"
    else:
        secret_line = f'secret   = "{binding.secret}"'
    lines = [
        "",
        "[[binding]]",
        f'name     = "{binding.name}"',
        f'injector = "{binding.injector}"',
        f'provider = "{binding.provider}"',
        secret_line,
        "hosts    = [" + ", ".join(f'"{h}"' for h in binding.hosts) + "]",
    ]
    if binding.placeholder is not None:
        lines.append(f'placeholder = "{binding.placeholder}"')
    if binding.env is not None:
        lines.append(f'env      = "{binding.env}"')
    block = "\n".join(lines) + "\n"
    if text and not text.endswith("\n"):
        text += "\n"
    ws.config_path.write_text(text + block)


def remove_binding(ws: Workspace, name: str) -> None:
    """Remove the named binding's `[[binding]]` block from the TOML via a
    surgical text edit. Raises ConfigError if no such binding exists."""
    text = ws.config_path.read_text()
    raw = tomllib.loads(text)
    bindings = _with_auto_names(_parse_bindings(raw, str(ws.config_path)))
    target = next((i for i, b in enumerate(bindings) if b.name == name), None)
    if target is None:
        raise ConfigError(f"binding '{name}' not found in {ws.config_path}")

    lines = text.splitlines(keepends=True)
    spans = _block_spans(text)
    start, end = spans[target]
    # Also drop one immediately-preceding blank separator line, if present,
    # so repeated add/remove doesn't accumulate blank lines.
    if start > 0 and lines[start - 1].strip() == "":
        start -= 1
    del lines[start:end]
    ws.config_path.write_text("".join(lines))


# ---- test (dry-run secret fetch) --------------------------------------------


@dataclass(frozen=True)
class BindingTestResult:
    name: str
    ok: bool
    value_len: int | None   # length of the fetched secret on success
    error: str | None       # error message on failure


def test_binding(
    binding: Binding,
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> BindingTestResult:
    """Exec the binding's provider and report success/failure WITHOUT
    revealing the secret values (only their total length). Resolves every slot
    in one batch invocation. Never raises a provider error -- it is captured
    into the result so callers can report per-binding in a batch."""
    from .errors import CredproxyError

    refs = secret_refs(binding)
    try:
        values = fetch_many(binding.provider, list(dict.fromkeys(refs.values())))
    except CredproxyError as e:
        return BindingTestResult(binding.name, False, None, str(e))
    total = sum(len(values[ref]) for ref in refs.values())
    return BindingTestResult(binding.name, True, total, None)


# ---- wire mapping (push path) -----------------------------------------------


def wire_config(
    bindings: list[Binding],
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> dict:
    """Resolve each binding's secret(s) and produce the proxy's bindings wire
    shape (design-v3, scheme-aware):

        {
          "bindings": [
            {
              "name":        <str>,
              "hosts":       [<str>, ...],
              "scheme":      <str>,            # selects the proxy mechanism
              "params":      {<str>: <any>},   # scheme-defined (e.g. header)
              "secret":      {<slot>: <real>}, # resolved values, keyed by slot
              "placeholder": <str>,            # substitute family; the token
                                               #   the proxy finds/swaps
              "env":         <str|null>,       # optional suggested env var
            },
            ...
          ]
        }

    Each `secret` value is the RAW fetched value -- substitute schemes replace
    only the placeholder substring inside whatever the client sent, so any
    surrounding format ("Bearer ", a base64 blob) is handled on the wire / by
    the scheme, not applied here. One batch provider invocation per binding.

    `fetch_many` is injected for testing; defaults to the real provider exec.
    """
    wire_bindings = []
    for b in bindings:
        injector = find_injector(b.injector)
        spec = get_scheme(injector.scheme)
        if spec.family == "substitute" and b.placeholder is None:
            raise ConfigError(
                f"binding '{b.name}' has no placeholder; materialize it first"
            )
        refs = secret_refs(b)
        values = fetch_many(b.provider, list(dict.fromkeys(refs.values())))
        secret = {slot: values[ref] for slot, ref in refs.items()}
        entry: dict = {
            "name": b.name,
            "hosts": list(b.hosts),
            "scheme": injector.scheme,
            "params": injector.params,
            "secret": secret,
        }
        if b.placeholder is not None:
            entry["placeholder"] = b.placeholder
        # env: prefer the binding-level override, fall back to the injector's
        # suggested env var, omit entirely if neither is set.
        env = b.env if b.env is not None else injector.env
        if env is not None:
            entry["env"] = env
        wire_bindings.append(entry)
    return {"bindings": wire_bindings}
