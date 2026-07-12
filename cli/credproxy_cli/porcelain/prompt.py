"""Loose-surface interactive prompting for pack expansion (#59).

Prompting is loose-surface-only by constitution (the strict surface never
prompts -- a standing architecture decision). These are the injectable seam the
`pack add` / `create` handlers reach for when, and only when, prompting is
enabled (`prompting_enabled(ctx)` -- loose AND stdin is a TTY). Every prompt
writes to STDERR and reads a line from stdin, mirroring the `_confirm_*` /
`ensure_proxy_image` gates (so a `--json` stdout stream is never corrupted).

Tests monkeypatch `ask_option` / `ask_provider` / `ask_secret` / `ask_injector`
/ `ask_hosts` to drive the resolution deterministically without a real TTY. The
last two extend the same seam for guided `binding add` (#75) -- one prompting
mechanism, so pack and binding prompting never drift on look/behavior.
"""
from __future__ import annotations

import sys


def prompting_enabled(ctx) -> bool:
    """Prompting fires only on the loose surface with a real TTY on stdin, and
    NOT under `--yes`. Strict (scriptable) and loose-without-a-TTY both fail closed
    toward the structured missing error -- never hang waiting on input. `--yes`
    is a non-interactive intent (take explicit -> default -> structured fail), so
    it suppresses prompting too (N1, mirroring the missing-proxy-image gate, where
    `--yes` builds/defaults without asking)."""
    return ctx.loose and sys.stdin.isatty() and not ctx.assume_yes


def _ask(prompt: str) -> str:
    """Write `prompt` to stderr and read one stripped line from stdin.

    A GENUINE EOF (closed/exhausted stdin -- `readline()` returns `""` with NO
    trailing newline) ABORTS the command via the structured `fail()` path (mirrors
    the `_confirm_*` gates' EOF->abort), so a required-value loop can never spin
    forever on a Ctrl-D (S1). An ENTERED empty line (`"\n"`) returns `""` and the
    caller re-prompts -- the distinction is exactly readline's `""` (EOF) vs
    `"\n"` (a bare Enter)."""
    from .render import fail
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if line == "":                       # EOF: no newline, distinct from "\n"
        fail("aborted: EOF at a required prompt (no input)")
    return line.strip()


# ---- pack options ------------------------------------------------------------


def ask_option(opt):
    """Prompt for one pack `[[option]]` value, returning a coerced/validated value
    (the caller passes it straight through -- `resolve_options` does not re-coerce
    a prompted value). Loops until valid. `string` = free text (empty accepts the
    default when one exists, else re-asks); `enum` = numbered pick; `bool` = y/n."""
    from ..core.model.packs import coerce_option_value

    desc = f" ({opt.description})" if opt.description else ""
    if opt.type == "bool":
        d = opt.default if opt.has_default else None
        suffix = "" if d is None else (" [Y/n]" if d else " [y/N]")
        while True:
            reply = _ask(f"option {opt.id}{desc} — true/false{suffix}: ").lower()
            if not reply and d is not None:
                return d
            if reply in ("y", "yes", "true"):
                return True
            if reply in ("n", "no", "false"):
                return False
            print(f"  please answer true/false", file=sys.stderr)
    if opt.type == "enum":
        for i, c in enumerate(opt.choices, 1):
            mark = "  (default)" if opt.has_default and c == opt.default else ""
            print(f"  {i}) {c}{mark}", file=sys.stderr)
        while True:
            reply = _ask(f"option {opt.id}{desc} — pick 1-{len(opt.choices)}: ")
            if not reply and opt.has_default:
                return opt.default
            if reply.isdigit() and 1 <= int(reply) <= len(opt.choices):
                return opt.choices[int(reply) - 1]
            if reply in opt.choices:
                return reply
            print(f"  not a valid choice", file=sys.stderr)
    # string
    while True:
        default_hint = f" [{opt.default}]" if opt.has_default else ""
        reply = _ask(f"option {opt.id}{desc}{default_hint}: ")
        if not reply:
            if opt.has_default:
                return opt.default
            print("  a value is required", file=sys.stderr)
            continue
        try:
            return coerce_option_value(opt, reply, f"option {opt.id}")
        except Exception as e:  # ConfigError -> re-ask
            print(f"  {e}", file=sys.stderr)


# ---- provider / secret -------------------------------------------------------


def ask_provider(default: str | None):
    """Prompt for a provider as an enum-style picker over the registry, the pack
    default preselected. Returns the chosen provider name. Loops until a resolvable
    provider is named (or the default is accepted)."""
    from ..core.providers import list_providers

    providers = [p.name for p in list_providers()]
    known = set(providers)
    for i, name in enumerate(providers, 1):
        mark = "  (default)" if name == default else ""
        print(f"  {i}) {name}{mark}", file=sys.stderr)
    while True:
        d = f" [{default}]" if default else ""
        reply = _ask(f"provider{d}: ")
        if not reply and default:
            return default
        if reply.isdigit() and 1 <= int(reply) <= len(providers):
            return providers[int(reply) - 1]
        if reply in known:
            return reply
        if reply:
            # A free-typed name that doesn't resolve: re-prompt rather than let
            # `find_provider` error out the whole command (N4, symmetric with the
            # secret validate-and-loop).
            print(f"  unknown provider {reply!r} -- pick one of: "
                  f"{', '.join(providers) or '(none registered)'}", file=sys.stderr)
            continue
        print("  a provider is required", file=sys.stderr)


def ask_secret(provider: str, default: str | None, slot: str | None = None):
    """Prompt for a secret ref (free text, provider-appropriate) then OFFER to
    validate it via the ad-hoc `binding test` fetch path -- report the fetched
    length (never the value) and loop on failure, turning a typo'd secret into an
    immediate fixable moment. Returns the accepted ref.

    `slot` names the injector slot this ref fills (multi-slot injectors like
    sigv4 prompt per declared slot, #71) -- shown in the prompt so the user knows
    which value is wanted; None (the single-slot `value` sugar) omits it."""
    from ..core.model import bindings as core_bindings

    label = f"secret for provider '{provider}'"
    if slot is not None:
        label += f" slot '{slot}'"
    while True:
        d = f" [{default}]" if default else ""
        ref = _ask(f"{label}{d} (a ref the provider understands): ")
        if not ref and default:
            ref = default
        if not ref:
            print("  a secret ref is required", file=sys.stderr)
            continue
        offer = _ask("validate it now (fetch, report length)? [Y/n] ").lower()
        if offer in ("n", "no"):
            return ref
        probe = core_bindings.Binding(
            name=f"{provider}-probe", injector="", provider=provider,
            secret=ref, hosts=(), placeholder=None, env=None)
        try:
            r = core_bindings.test_binding(probe)
        except Exception as e:            # provider resolution error, etc.
            print(f"  validation error: {e} — try again", file=sys.stderr)
            continue
        if r.ok:
            print(f"  ok: fetched {r.value_len} chars", file=sys.stderr)
            return ref
        print(f"  fetch failed: {r.error or 'unknown error'} — try again",
              file=sys.stderr)


# ---- injector / hosts (guided `binding add`, #75) ----------------------------


def ask_injector(default: str | None = "bearer"):
    """Prompt for an injector as an enum-style picker over the registry (name +
    the scheme it runs), `bearer` -- the overwhelmingly common case -- preselected
    when it resolves. Mirrors `ask_provider`'s look/behavior. Returns the chosen
    injector name; loops until a resolvable injector is named (or the default is
    accepted)."""
    from ..core.model.injectors import list_injectors

    injectors = list_injectors()
    names = [d.name for d in injectors]
    known = set(names)
    has_default = default in known
    for i, d in enumerate(injectors, 1):
        scheme = d.scheme if d.scheme != "script" else f"script:{d.spec.family}"
        mark = "  (default)" if has_default and d.name == default else ""
        print(f"  {i}) {d.name} — {scheme}{mark}", file=sys.stderr)
    while True:
        dhint = f" [{default}]" if has_default else ""
        reply = _ask(f"injector{dhint}: ")
        if not reply and has_default:
            return default
        if reply.isdigit() and 1 <= int(reply) <= len(names):
            return names[int(reply) - 1]
        if reply in known:
            return reply
        if reply:
            # A free-typed name that doesn't resolve: re-prompt rather than let
            # `find_injector` error out the whole command (symmetric with
            # ask_provider's unknown-name loop).
            print(f"  unknown injector {reply!r} -- pick one of: "
                  f"{', '.join(names) or '(none registered)'}", file=sys.stderr)
            continue
        print("  an injector is required", file=sys.stderr)


def ask_hosts():
    """Prompt for one or more host scopes, free text, repeatable until an empty
    line. Each is validated through `core/model/hostmatch` immediately, so a bad
    glob (e.g. the `*.com` rejection) loops with the error instead of failing the
    whole add. Returns the accepted list (never empty -- the first host is
    required)."""
    from ..core.model import hostmatch

    hosts: list[str] = []
    while True:
        tail = "empty to finish" if hosts else "e.g. api.example.com or *.example.com"
        reply = _ask(f"host ({tail}): ")
        if not reply:
            if hosts:
                return hosts
            print("  at least one host is required", file=sys.stderr)
            continue
        if hostmatch.is_pattern(reply):
            err = hostmatch.validate_pattern(reply)
            if err:
                print(f"  {err} — try again", file=sys.stderr)
                continue
        hosts.append(reply)
