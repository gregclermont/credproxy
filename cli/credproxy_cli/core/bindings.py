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

import json
import re
from dataclasses import dataclass, replace
from typing import Callable

from . import hostmatch
from .errors import ConfigError, CredproxyError
from .injectors import Injector, find_injector
from .paths import atomic_write_text as _atomic_write_text
from .providers import fetch_many as provider_fetch_many
from .schemes import location_key
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


def _refs_by_provider(bindings: list[Binding]) -> dict[str, list[str]]:
    """Group the bindings' secret refs by provider, deduped and
    order-preserving: `{provider: [ref, ...]}`. Taking the union across every
    binding that names a provider is what lets the caller resolve that provider
    ONCE (one batch invocation) instead of once per binding."""
    buckets: dict[str, dict[str, None]] = {}
    for b in bindings:
        bucket = buckets.setdefault(b.provider, {})
        for ref in secret_refs(b).values():
            bucket[ref] = None  # dict preserves insertion order, dedups refs
    return {provider: list(refs) for provider, refs in buckets.items()}


def resolve_secrets(
    bindings: list[Binding],
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> dict[str, dict[str, str]]:
    """Resolve every binding's secret(s) with ONE provider invocation per
    distinct provider -- the batch carries the union of refs across all bindings
    that share it. So a provider with a costly setup (a vault that must unlock,
    a session that must authenticate) pays that cost once per resolve, not once
    per binding. Returns `{provider: {ref: value}}`.

    `fetch_many` is injected for testing; defaults to the real provider exec."""
    return {
        provider: fetch_many(provider, refs)
        for provider, refs in _refs_by_provider(bindings).items()
    }


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
    # (host, location) -> {"unconditional": name|None, "by_ph": {placeholder: name}}.
    # Two bindings may share a wire location only if each has a distinct
    # placeholder (the request carries one, so the match is unambiguous -- lets
    # several re-seal bindings share a token endpoint). Sign-family bindings have
    # no placeholder and write unconditionally, so they can't share. Mirrors
    # proxy/config.load_resolved.
    seen_loc: dict[tuple, dict] = {}
    for b in bindings:
        if b.name is None:
            # Should not happen post-materialize; defensive.
            raise ConfigError(f"{source}: a binding is missing a name")
        if b.name in names:
            raise ConfigError(f"{source}: duplicate binding name '{b.name}'")
        names.add(b.name)

        # A `*`-bearing host is a glob pattern; validate it strictly (mirrors
        # proxy/hostmatch.py) so a too-broad pattern is caught at `binding add`,
        # not only when the proxy validates the pushed config.
        for host in b.hosts:
            if hostmatch.is_pattern(host):
                err = hostmatch.validate_pattern(host)
                if err:
                    raise ConfigError(f"{source}: binding '{b.name}': {err}")

        # injector + provider must exist (raises InjectorError/ProviderError).
        injector = find_injector(b.injector)
        find_provider(b.provider)
        # A scripted injector names a .star file; resolve it now so a missing
        # or mistyped script is caught here (add/apply time) rather than going
        # unnoticed until the proxy compiles it at push.
        if injector.scheme == "script" and injector.script:
            from .scripts import find_script
            try:
                find_script(injector.script)
            except CredproxyError as e:
                raise ConfigError(f"{source}: binding '{b.name}': {e}")
        spec = injector.spec

        # Required params (e.g. oauth2-reseal's api_hosts): missing/empty would be
        # a fail-OPEN at the proxy (on_response can't mint, so the real token
        # response would reach the workspace), so reject at add/apply time rather
        # than only at proxy push. Mirrors proxy/config.load_resolved.
        for rp in spec.required_params:
            pv = injector.params.get(rp)
            if pv is None or (isinstance(pv, (str, list)) and len(pv) == 0):
                raise ConfigError(
                    f"{source}: binding '{b.name}' injector '{b.injector}' "
                    f"(scheme '{injector.scheme}') requires a non-empty param '{rp}'"
                )

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
            # Lower-case the host: DNS is case-insensitive, and the proxy
            # lower-cases at match time, so two bindings on `API.x`/`api.x` must
            # be caught here too (mirrors proxy/config.load_resolved).
            group = seen_loc.setdefault((host.lower(), loc),
                                        {"unconditional": None, "by_ph": {}})
            if not spec.uses_placeholder:
                other = group["unconditional"] or next(iter(group["by_ph"].values()), None)
                if other is not None:
                    raise ConfigError(
                        f"{source}: bindings '{other}' and '{b.name}' both write "
                        f"{loc[0]} on host '{host}' (a binding with no placeholder "
                        f"writes unconditionally and can't share a wire location)"
                    )
                group["unconditional"] = b.name
            else:
                if group["unconditional"] is not None:
                    raise ConfigError(
                        f"{source}: bindings '{group['unconditional']}' and "
                        f"'{b.name}' both write {loc[0]} on host '{host}' (a binding "
                        f"with no placeholder writes unconditionally and can't share "
                        f"a wire location)"
                    )
                # Placeholders sharing a wire location must be DISJOINT, not just
                # distinct: substitution is sequential str.replace, so `ph` vs
                # `ph2` (one a substring of the other) would corrupt the longer.
                # Mirrors proxy/config.load_resolved. (Skip the `\x00name`
                # sentinels used for not-yet-materialized placeholders.)
                if b.placeholder is not None:
                    for existing_ph, existing_name in group["by_ph"].items():
                        if existing_ph.startswith("\x00"):
                            continue
                        if existing_ph == b.placeholder:
                            raise ConfigError(
                                f"{source}: bindings '{existing_name}' and "
                                f"'{b.name}' both write {loc[0]} on host '{host}' "
                                f"with the same placeholder '{b.placeholder}'"
                            )
                        if existing_ph in b.placeholder or b.placeholder in existing_ph:
                            raise ConfigError(
                                f"{source}: bindings '{existing_name}' and "
                                f"'{b.name}' share {loc[0]} on host '{host}' but "
                                f"their placeholders '{existing_ph}' and "
                                f"'{b.placeholder}' overlap (one is a substring of "
                                f"the other); sequential substitution would corrupt "
                                f"the other"
                            )
                # An unmaterialized placeholder (None) will become a distinct
                # random value, so key it by name to keep it from colliding.
                group["by_ph"][b.placeholder or f"\x00{b.name}"] = b.name


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

# A `[[binding]]` table header line (a trailing comment is allowed).
_BLOCK_HEADER_RE = re.compile(r"^\s*\[\[\s*binding\s*\]\]\s*(#.*)?$")
# Any genuine top-level table / array-of-tables header (ends the current block).
# Matches a fully-bracketed header line (+ optional comment) -- NOT a line that
# merely starts with '[', such as a multi-line array value's continuation
# (`[1, 2],`), which `^\s*\[` used to mistake for a table and split a block on.
_TABLE_HEADER_RE = re.compile(r"^\s*\[\[?[^\[\]\n]+\]\]?\s*(#.*)?$")


def _array_depth_delta(line: str) -> int:
    """Net unclosed '[' contributed by `line`, ignoring brackets inside comments
    and single-line string literals. Lets `_block_spans` track when it is INSIDE
    a multi-line array value, so the value's continuation lines aren't mistaken
    for a table header (which would split a `[[binding]]` block in the wrong
    place) and a multi-line array isn't cut mid-value.

    Known limitation: multi-line strings (\"\"\"/''') are not tracked -- credproxy
    only ever writes single-line, newline-escaped values (see `_toml_str`), so
    its own files never contain them."""
    depth = 0
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == "#":
            break  # comment runs to end of line
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n and line[i] != quote:
                if quote == '"' and line[i] == "\\":
                    i += 1  # skip an escaped char in a basic string
                i += 1
            i += 1  # past the closing quote (or EOL on an unterminated string)
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        i += 1
    return depth


def _block_spans(text: str, header_re: re.Pattern = _BLOCK_HEADER_RE,
                 child_re: re.Pattern | None = None) -> list[tuple[int, int]]:
    """Index the `[[binding]]` blocks in `text` by line range [start, end)
    (end exclusive), where `start` is the header line and the block runs to
    the next table header or EOF. Trailing blank lines stay OUTSIDE the block
    so inserts land tightly.

    Array-bracket depth is tracked so a multi-line array value (e.g. a multi-line
    `hosts = [ ... ]`) is never split mid-value and a `[`-led array line is never
    mistaken for a table header. The returned spans are 1:1 with the `[[binding]]`
    tables tomllib parses, in file order -- materialize/remove index into them by
    binding position, so a miscount would edit the wrong block.

    `header_re` selects which array-of-tables to index (default `[[binding]]`);
    the rules layer passes its own `[[rule]]` header regex to reuse this
    array-depth-aware machinery verbatim. `child_re` (e.g. `[rule.headers]`)
    matches a sub-table header that BELONGS to the current element and so must be
    folded INTO its span rather than ending it -- otherwise removing the block
    would orphan the child table and corrupt the file."""
    lines = text.splitlines(keepends=True)
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(lines)
    depth = 0  # unclosed array brackets carried across lines (multi-line arrays)
    while i < n:
        if depth == 0 and header_re.match(lines[i]):
            start = i
            depth = max(0, depth + _array_depth_delta(lines[i]))
            j = i + 1
            while j < n:
                if depth == 0 and _TABLE_HEADER_RE.match(lines[j]) \
                        and not (child_re is not None and child_re.match(lines[j])):
                    break
                depth = max(0, depth + _array_depth_delta(lines[j]))
                j += 1
            # Trim trailing blank lines from the block end.
            end = j
            while end - 1 > start and lines[end - 1].strip() == "":
                end -= 1
            spans.append((start, end))
            i = j
        else:
            depth = max(0, depth + _array_depth_delta(lines[i]))
            i += 1
    return spans


# A TOML bare key (unquoted): letters, digits, '_', '-'. Anything else must be
# emitted as a quoted key.
_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+$")


def _toml_str(value: str) -> str:
    """Render `value` as a TOML basic-string literal (quoted + escaped).

    Values written into the config (secret refs, hosts, env, placeholder, name)
    are user-supplied; interpolating them raw would let a `"`, `\\`, or newline
    corrupt the file or inject TOML. This escapes per the TOML basic-string
    rules so any value round-trips."""
    out = ['"']
    for ch in value:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch < " " or ch == "\x7f":
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_key(key: str) -> str:
    """A TOML key: bare when it's a safe identifier, else a quoted literal."""
    return key if _BARE_KEY_RE.match(key) else _toml_str(key)


def _insert_line_in_block(text: str, block_index: int, line: str,
                          header_re: re.Pattern = _BLOCK_HEADER_RE,
                          child_re: re.Pattern | None = None) -> str:
    """Insert `line` (a scalar key, no trailing newline) into the block-index'th
    `[[binding]]` block, preserving everything else verbatim. When `child_re` is
    given, the line lands BEFORE the first child sub-table (`[binding.x]`) in the
    block -- a scalar key after a sub-table header would belong to that sub-table,
    not the array element."""
    lines = text.splitlines(keepends=True)
    spans = _block_spans(text, header_re, child_re)
    start, end = spans[block_index]
    at = end
    if child_re is not None:
        for k in range(start + 1, end):
            if child_re.match(lines[k]):
                at = k
                break
    # Ensure the line before insertion ends with a newline.
    if at > 0 and not lines[at - 1].endswith("\n"):
        lines[at - 1] = lines[at - 1] + "\n"
    lines.insert(at, line + "\n")
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
            text = _insert_line_in_block(text, idx, f'name = {_toml_str(res.name)}')
            notify(f"materialized name '{res.name}' for binding [{idx}]")
            changed = True
        if orig.placeholder is None:
            injector = find_injector(res.injector)
            # Only the substitute family holds an inert placeholder; sign
            # schemes (sigv4, ...) compute auth material and have none.
            if injector.spec.uses_placeholder:
                ph = injector.placeholder.generate()
                text = _insert_line_in_block(text, idx, f'placeholder = {_toml_str(ph)}')
                resolved[idx] = replace(res, placeholder=ph)
                notify(f"materialized placeholder for binding '{res.name}'")
                changed = True

    if changed:
        _atomic_write_text(ws.config_path, text)

    validate(resolved, source)
    return resolved


# ---- imperative edits -------------------------------------------------------


def _render_binding_block(binding: Binding) -> str:
    """Render a fully-formed `[[binding]]` block (with a leading blank line),
    escaping every interpolated value so it round-trips as valid TOML."""
    if isinstance(binding.secret, dict):
        # Multi-slot: an inline table keeps the mapping inside the [[binding]]
        # element (a [binding.secret] sub-table is invalid under array-of-tables).
        inner = ", ".join(f'{_toml_key(slot)} = {_toml_str(ref)}'
                          for slot, ref in binding.secret.items())
        secret_line = f"secret   = {{ {inner} }}"
    else:
        secret_line = f'secret   = {_toml_str(binding.secret)}'
    lines = [
        "",
        "[[binding]]",
        f'name     = {_toml_str(binding.name)}',
        f'injector = {_toml_str(binding.injector)}',
        f'provider = {_toml_str(binding.provider)}',
        secret_line,
        "hosts    = [" + ", ".join(_toml_str(h) for h in binding.hosts) + "]",
    ]
    if binding.placeholder is not None:
        lines.append(f'placeholder = {_toml_str(binding.placeholder)}')
    if binding.env is not None:
        lines.append(f'env      = {_toml_str(binding.env)}')
    return "\n".join(lines) + "\n"


def append_bindings(ws: Workspace, bindings: list[Binding]) -> None:
    """Append one or more `[[binding]]` blocks in a SINGLE write, so a
    multi-binding add (e.g. a preset) lands atomically rather than leaving a
    partial set on a mid-loop failure."""
    text = ws.config_path.read_text()
    if text and not text.endswith("\n"):
        text += "\n"
    _atomic_write_text(
        ws.config_path, text + "".join(_render_binding_block(b) for b in bindings))


def append_binding(ws: Workspace, binding: Binding) -> None:
    """Append a single `[[binding]]` block to the workspace TOML."""
    append_bindings(ws, [binding])


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
    _atomic_write_text(ws.config_path, "".join(lines))


# ---- test (dry-run secret fetch) --------------------------------------------


@dataclass(frozen=True)
class BindingTestResult:
    name: str
    ok: bool
    value_len: int | None   # length of the fetched secret on success
    error: str | None       # error message on failure
    note: str | None = None  # advisory (e.g. scripted injector: script resolved)


def test_bindings(
    bindings: list[Binding],
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> list[BindingTestResult]:
    """Dry-run a set of bindings, batching provider calls: ONE invocation per
    distinct provider (the union of refs across the bindings that share it), so
    a costly provider unlocks once for the whole set rather than once per
    binding. Results stay per-binding and in input order; secret values are
    never revealed (only their total length). Never raises a provider error --
    each is captured into its result.

      - Injector/script resolution is checked per binding (no provider call); a
        failure there fails that binding only and skips its fetch.
      - If a provider's batch fetch fails, the batch error can't say which ref
        was at fault, so we re-fetch that provider's bindings individually to
        pin the failure to the right binding(s). The provider's setup is
        typically still warm, so this costs extra only on the error path.
    """
    # Phase 1: per-binding injector/script check. For a scripted injector,
    # confirm the named .star resolves -- the proxy compiles it at push time, so
    # a passing `binding test` shouldn't falsely imply a missing script is fine.
    early: dict[int, BindingTestResult] = {}   # index -> pre-fetch failure
    notes: dict[int, str] = {}                 # index -> advisory note
    for i, b in enumerate(bindings):
        if not b.injector:
            continue
        try:
            inj = find_injector(b.injector)
        except CredproxyError as e:
            early[i] = BindingTestResult(b.name, False, None, str(e))
            continue
        if inj.scheme == "script" and inj.script:
            from .scripts import find_script
            try:
                find_script(inj.script)
                notes[i] = f"script '{inj.script}' resolved (not compiled)"
            except CredproxyError as e:
                early[i] = BindingTestResult(b.name, False, None, str(e))

    # Phase 2: one batch fetch per provider, over the bindings that survived the
    # injector check.
    fetchable = [b for i, b in enumerate(bindings) if i not in early]
    resolved: dict[str, dict[str, str]] = {}
    degraded: set[str] = set()  # providers whose batch failed -> per-binding retry
    for provider, refs in _refs_by_provider(fetchable).items():
        try:
            resolved[provider] = fetch_many(provider, refs)
        except CredproxyError:
            degraded.add(provider)

    # Phase 3: assemble per-binding results in input order.
    results: list[BindingTestResult] = []
    for i, b in enumerate(bindings):
        if i in early:
            results.append(early[i])
            continue
        # Sum over distinct fetched values, not per-slot, so a ref shared by two
        # slots is counted once.
        distinct_refs = list(dict.fromkeys(secret_refs(b).values()))
        if b.provider in degraded:
            try:
                values = fetch_many(b.provider, distinct_refs)
            except CredproxyError as e:
                results.append(BindingTestResult(b.name, False, None, str(e)))
                continue
        else:
            values = resolved[b.provider]
        total = sum(len(values[ref]) for ref in distinct_refs)
        results.append(BindingTestResult(b.name, True, total, None, notes.get(i)))
    return results


def test_binding(
    binding: Binding,
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> BindingTestResult:
    """Dry-run a single binding. Thin wrapper over `test_bindings`, kept for the
    ad-hoc `binding test --provider ... --secret ...` probe and other
    single-binding callers."""
    return test_bindings([binding], fetch_many)[0]


# ---- wire mapping (push path) -----------------------------------------------


def config_fingerprint(bindings: list[Binding]) -> str:
    """A stable hash of the bindings' wire METADATA -- name, hosts, scheme,
    params, placeholder, EFFECTIVE env, provider, the secret REFS (not resolved
    values), and for a scripted injector its source + compile metadata
    (api/family/slots/location_kind/header_default). Mirrors everything
    wire_config pushes (minus resolved secret values) so a change to any pushed
    field re-pushes. Lets the host tell whether the proxy already holds the
    intended config WITHOUT re-resolving any secret, so it is cheap
    (injector/script TOML reads only, never a provider call).

    It deliberately excludes resolved secret VALUES, so an in-place secret
    rotation (same ref, new value) does NOT change the fingerprint -- refresh
    that with an explicit re-push (`enter --push` / `apply`)."""
    import hashlib

    blob = json.dumps(_fingerprint_items(bindings), sort_keys=True,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _fingerprint_items(bindings: list[Binding]) -> list[dict]:
    """The per-binding wire-metadata dicts hashed by `config_fingerprint`.
    Exposed so the rules layer can fold bindings + rules into one combined
    fingerprint (see core/rules.combined_fingerprint) without duplicating the
    field selection."""
    items = []
    for b in sorted(bindings, key=lambda x: x.name or ""):
        injector = find_injector(b.injector)
        spec = injector.spec
        entry = {
            "name": b.name,
            "hosts": sorted(b.hosts),
            "scheme": injector.scheme,
            "params": injector.params,
            "placeholder": b.placeholder,
            # EFFECTIVE env -- the same fallback wire_config pushes, so editing
            # the injector's suggested env (with no binding override) re-pushes.
            "env": b.env if b.env is not None else injector.env,
            "provider": b.provider,
            "secret": b.secret,
        }
        if injector.scheme == "script" and injector.script:
            from .scripts import find_script
            # The proxy compiles the script with this metadata, so all of it is
            # part of the pushed config (mirrors wire_config) -- include it so an
            # injector-manifest edit (family/slots/location/api/...) re-pushes.
            entry["script_source"] = find_script(injector.script).source
            entry["api"] = injector.api
            entry["family"] = spec.family
            entry["slots"] = list(spec.slots)
            entry["location_kind"] = spec.location_kind
            entry["header_default"] = spec.header_default
        items.append(entry)
    return items


def wire_config(
    bindings: list[Binding],
    fetch_many: Callable[[str, list[str]], dict[str, str]] = provider_fetch_many,
) -> dict:
    """Resolve each binding's secret(s) and produce the proxy's bindings wire
    shape (scheme-aware):

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
    the scheme, not applied here. Secrets are resolved with one provider
    invocation per distinct provider (the union of refs across the bindings that
    share it -- see `resolve_secrets`), so a costly provider unlocks once.

    `fetch_many` is injected for testing; defaults to the real provider exec.
    """
    from .scripts import find_script

    prepared = [(b, find_injector(b.injector)) for b in bindings]
    # Validate placeholders BEFORE resolving anything, so a config error aborts
    # without first paying a provider's setup cost (e.g. unlocking a vault).
    for b, injector in prepared:
        if injector.spec.uses_placeholder and b.placeholder is None:
            raise ConfigError(
                f"binding '{b.name}' has no placeholder; materialize it first"
            )

    resolved = resolve_secrets(bindings, fetch_many)

    wire_bindings = []
    for b, injector in prepared:
        spec = injector.spec
        refs = secret_refs(b)
        values = resolved[b.provider]
        secret = {slot: values[ref] for slot, ref in refs.items()}
        entry: dict = {
            "name": b.name,
            "hosts": list(b.hosts),
            "scheme": injector.scheme,
            "params": injector.params,
            "secret": secret,
        }
        if injector.scheme == "script":
            # Push the script SOURCE plus the metadata the proxy can't infer
            # (the CLI can't run Starlark): the proxy compiles it into a
            # ScriptedScheme. The push model -- proxy stays stateless.
            entry["script"] = injector.script
            entry["script_source"] = find_script(injector.script).source
            entry["api"] = injector.api
            entry["family"] = spec.family
            entry["slots"] = list(spec.slots)
            entry["location_kind"] = spec.location_kind
            entry["header_default"] = spec.header_default
        if b.placeholder is not None:
            entry["placeholder"] = b.placeholder
        # env: prefer the binding-level override, fall back to the injector's
        # suggested env var, omit entirely if neither is set.
        env = b.env if b.env is not None else injector.env
        if env is not None:
            entry["env"] = env
        wire_bindings.append(entry)
    return {"bindings": wire_bindings}
