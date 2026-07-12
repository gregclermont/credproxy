"""The `binding` noun: add/remove/list/test handlers, the `--secret` parser, and
the argparse subparser builder for the binding verb tree."""
from __future__ import annotations

import argparse
import sys

from ..core.errors import CredproxyError
from . import render
from .render import fail
from .common import Ctx, _resolve_ws, _require_exists


def _parse_secret_args(
    values: list[str] | None, slots: tuple[str, ...] = (),
) -> str | dict[str, str] | None:
    """Turn repeated --secret values into a single bare ref (single-slot) or a
    slot->ref table (multi-slot).

    A lone --secret is a bare ref kept verbatim even if it contains '=' (e.g. a
    vault path with a query string) -- UNLESS it is written `SLOT=REF` and SLOT
    is one of the injector's declared `slots`, in which case it is that named
    slot (so `--secret private_key=REF` works for a single non-`value` slot like
    jwt-bearer's). Multi-slot requires two or more SLOT=REF flags; each is split
    on its first '=', so a REF may itself contain '='. Splitting on a declared
    slot name (not just any '=') is what keeps a lone `=`-containing ref
    unambiguous."""
    if not values:
        return None
    if len(values) == 1:
        slot, sep, ref = values[0].partition("=")
        if sep and ref and slot in slots:
            return {slot: ref}        # a single, explicitly-named slot
        return values[0]              # bare ref (the single-slot `value` sugar)
    out: dict[str, str] = {}
    for v in values:
        slot, sep, ref = v.partition("=")
        if not sep or not slot or not ref:
            fail(f"--secret '{v}' must be SLOT=REF for a multi-slot secret")
        if slot in out:
            fail(f"--secret slot '{slot}' given more than once")
        out[slot] = ref
    return out


def _missing_binding_flags(a: argparse.Namespace) -> list[str]:
    missing = []
    if a.injector is None:
        missing.append("--injector")
    if not a.provider:
        missing.append("--provider")
    if not a.host:
        missing.append("--host")
    if not a.secret:
        missing.append("--secret")
    return missing


def _prompt_secret_flags(prompt_mod, provider: str, slots: tuple[str, ...]) -> list[str]:
    """Prompt for the secret ref(s) as `--secret`-shaped strings that round-trip
    through `_parse_secret_args`: a single bare ref for the single-slot `value`
    sugar, or one `SLOT=REF` per declared slot for a multi-slot injector (#71 --
    each slot prompted separately via the shared `ask_secret` seam)."""
    if slots == ("value",):
        return [prompt_mod.ask_secret(provider, None)]
    return [f"{s}={prompt_mod.ask_secret(provider, None, slot=s)}" for s in slots]


def do_binding_add(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core.model import bindings as core_bindings
    from ..core.model.bindings import Binding
    from ..core.model.injectors import find_injector
    from ..core.providers import find_provider
    from . import prompt as prompt_mod

    # `--secret` is checked at the arg level here (its slot shape needs the
    # resolved injector, validated below once it's present).
    missing = _missing_binding_flags(a)

    ws = None
    injector = None
    guided = False
    if missing and prompt_mod.prompting_enabled(ctx):
        # Guided path (loose + TTY, #75): walk the user through the gaps instead
        # of erroring, extending the #59 prompt seam. Resolve the workspace FIRST
        # so a bad NAME fails fast, before the user answers any prompt. Supplied
        # flags are skipped (partial flags + prompts compose); --name/--env/
        # --placeholder keep their defaults and are never prompted.
        ws = _resolve_ws(ctx, name)
        _require_exists(ws)
        guided = True
        if a.injector is None:
            a.injector = prompt_mod.ask_injector()
        # Resolve the injector now: its declared slots drive per-slot secret
        # prompting, and it's needed downstream regardless.
        injector = find_injector(a.injector)
        if not a.provider:
            a.provider = prompt_mod.ask_provider(None)
        if not a.secret:
            a.secret = _prompt_secret_flags(prompt_mod, a.provider, injector.spec.slots)
        if not a.host:
            a.host = prompt_mod.ask_hosts()
        missing = _missing_binding_flags(a)

    if missing:
        # Strict / loose-without-a-TTY: report EVERY missing required flag at once
        # (like `doctor`), with a copy-pasteable skeleton -- not one-at-a-time,
        # where each retry reveals the next gap (issue #74 F).
        msg = (f"`binding add` missing: {', '.join(missing)}; "
               f"e.g. {render.cmd(render.EX_BINDING_ADD)}")
        if a.injector is None:
            # A wholly-flagless add is often someone reaching for a coordinated
            # set -- point at packs (which is the minimal-flags path anyway).
            msg += (f"\n(for a coordinated multi-binding set + guardrails, use a "
                    f"pack: {render.cmd(render.EX_PACK_ADD)})")
        fail(msg)

    if ws is None:
        ws = _resolve_ws(ctx, name)
        _require_exists(ws)

    if injector is None:
        injector = find_injector(a.injector)
    find_provider(a.provider)

    # Parse --secret with the injector's declared slots, so a lone
    # `--secret SLOT=REF` for a single named slot (e.g. jwt-bearer's
    # private_key) is recognized rather than swallowed as a bare `value` ref.
    # (`a.secret` is already guaranteed non-empty by the missing-flag check
    # above, so this never returns None.)
    secret = _parse_secret_args(a.secret, injector.spec.slots)

    # Lock the read-validate-write: two concurrent `binding add` must not both
    # read the same file, pick the same auto-name, and last-writer-wins (the
    # per-file atomic write prevents a torn file, not a lost update).
    with ws.lock():
        existing = core_bindings.load_bindings(ws)
        taken = {b.name for b in existing}
        bname = a.binding_name or core_bindings._auto_name(a.injector, a.provider, taken)
        if bname in taken:
            fail(f"binding name '{bname}' already exists in workspace '{ws.name}'")

        # An explicit --placeholder is written into the block (hand-owned, wins);
        # otherwise the placeholder is LOCK-managed -- nothing is written into the
        # TOML, and resolve_workspace mints its identity into the lock below.
        placeholder = a.placeholder
        # `--no-env` writes `env = false` (suppress the injector's hint); else
        # bake the effective env (explicit override, or the injector's hint) so
        # the file records the concrete choice.
        if a.no_env:
            env = None
            env_suppressed = True
        else:
            env = a.env or injector.env
            env_suppressed = False

        binding = Binding(
            name=bname,
            injector=a.injector,
            provider=a.provider,
            secret=secret,
            hosts=tuple(a.host),
            placeholder=placeholder,
            env=env,
            env_suppressed=env_suppressed,
        )
        core_bindings.validate(existing + [binding], str(ws.config_path))

        # Snapshot BEFORE appending: resolve_workspace below runs the full
        # container-half + wire validation, so a PRE-EXISTING unrelated error
        # (missing image, bad [[mounts]]) would raise AFTER the block is on disk,
        # leaving the hand-owned file half-written. Restore on any failure.
        original = ws.config_path.read_text()
        core_bindings.append_binding(ws, binding)

        # Mint the (lock-managed) placeholder identity now, so it is stable for a
        # later `resolve`/`push --config` -- resolve_workspace re-validates the
        # whole file and records generated placeholders into the lock.
        from ..core.model.lock import save_lock
        from ..core.model.resolver import resolve_workspace
        from ..core.paths import atomic_write_text
        try:
            resolved = resolve_workspace(ws)
        except CredproxyError as e:
            atomic_write_text(ws.config_path, original)  # never half-write
            fail(f"binding not added: workspace '{ws.name}' config has a "
                 f"pre-existing error: {e}")
        if resolved.lock_dirty:
            save_lock(ws, resolved.lock)
        placeholder = next((b.placeholder for b in resolved.bindings
                            if b.name == bname), placeholder)

    from ..core.model import config as core_config
    render.OUT.binding_added(bname, ws.name, {
        "name": bname,
        "injector": binding.injector,
        "provider": binding.provider,
        "secret": binding.secret,
        "hosts": list(binding.hosts),
        "placeholder": placeholder,
        "env": env,
    }, attached=core_config.quick_attach(ws))

    if guided:
        # The teaching moment: echo the equivalent fully-flagged form so the
        # guided path makes itself unnecessary next time (#75). Any optional
        # flags the user DID supply (--name/--env/--no-env/--placeholder) ride
        # along so the echo actually reproduces this binding, not a variant.
        render.say(f"equivalent to: {render.cmd(_binding_add_tail(binding, a))}")


def _binding_add_tail(binding, a: argparse.Namespace) -> str:
    """The `binding add ...` verb+flags that reproduce `binding` non-interactively
    (for the guided-path teaching echo). Every value is shell-quoted so a glob
    host (`*.amazonaws.com`) or a ref with shell metacharacters pastes verbatim
    without the shell expanding it. `render.cmd` prepends the surface's spelling
    (`credp ...` on loose, where guided prompting lives)."""
    import shlex

    def q(v: str) -> str:
        return shlex.quote(v)

    parts = ["binding add",
             f"--injector {q(binding.injector)}",
             f"--provider {q(binding.provider)}"]
    if isinstance(binding.secret, dict):
        parts += [f"--secret {q(f'{slot}={ref}')}"
                  for slot, ref in binding.secret.items()]
    else:
        parts.append(f"--secret {q(binding.secret)}")
    parts += [f"--host {q(h)}" for h in binding.hosts]
    # Optional flags: echo only the ones the user explicitly supplied (the
    # guided path never prompts for these -- they kept their flag-or-default).
    if a.binding_name is not None:
        parts.append(f"--name {q(a.binding_name)}")
    if a.no_env:
        parts.append("--no-env")
    elif a.env is not None:
        parts.append(f"--env {q(a.env)}")
    if a.placeholder is not None:
        parts.append(f"--placeholder {q(a.placeholder)}")
    return " ".join(parts)


def do_binding_remove(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core.model import bindings as core_bindings
    from .common import _confirm_destructive

    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "remove binding from")
    with ws.lock():                          # atomic read-modify-write of the TOML
        core_bindings.remove_binding(ws, a.binding_name)
    render.OUT.binding_removed(a.binding_name, ws.name)


def do_binding_list(ctx: Ctx, name: str | None) -> None:
    from ..core.model.resolver import resolve_workspace

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Read-only: resolve placeholders from the lock in memory, never persist (a
    # not-yet-persisted placeholder is ephemeral until start/push/add/test mints
    # it into the lock).
    bindings = resolve_workspace(ws).bindings
    rows = [
        {
            "name": b.name,
            "injector": b.injector,
            "provider": b.provider,
            "secret": b.secret,
            "hosts": list(b.hosts),
            "placeholder": b.placeholder,
            "env": b.env,
        }
        for b in bindings
    ]
    render.OUT.binding_list(ws.name, rows)


def do_binding_test(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core.model import bindings as core_bindings

    # Ad-hoc mode: `binding test --provider P --secret REF [--injector I]`
    # exercises a definition before it is bound -- no workspace involved.
    if a.injector is not None or a.provider is not None or a.secret is not None:
        _do_binding_test_adhoc(ctx, name, a)
        return

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Resolve placeholders from the lock and PERSIST it: `binding test` mints the
    # placeholder identity a later `push --config` (from `resolve`) relies on. The
    # provider fetch below needs no lock (and can be slow).
    from ..core.model.lock import save_lock
    from ..core.model.resolver import resolve_workspace
    with ws.lock():
        resolved = resolve_workspace(ws)
        if resolved.lock_dirty:
            save_lock(ws, resolved.lock)
    bindings = resolved.bindings
    if a.binding_name is not None:
        bindings = [b for b in bindings if b.name == a.binding_name]
        if not bindings:
            fail(f"binding '{a.binding_name}' not found in workspace '{ws.name}'")

    # Batch by provider: a workspace whose bindings share one provider (e.g. a
    # vault) resolves it once for the whole `binding test`, not once per binding.
    results = []
    any_fail = False
    for b, r in zip(bindings, core_bindings.test_bindings(bindings)):
        if not r.ok:
            any_fail = True
        results.append({
            "name": b.name,
            "provider": b.provider,
            "ok": r.ok,
            "value_len": r.value_len,
            "error": r.error,
            "note": r.note,
        })
    render.OUT.binding_test(results)
    if any_fail:
        sys.exit(1)


def _do_binding_test_adhoc(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    """Standalone test of a definition before it is bound: resolve the
    injector/provider, exec the provider, report ok/length. No workspace."""
    from ..core.model import bindings as core_bindings
    from ..core.model.injectors import find_injector
    from ..core.providers import find_provider

    if a.binding_name is not None:
        fail("cannot combine a binding NAME with ad-hoc --provider/--secret")

    # Resolve the injector first (if any) so its declared slots disambiguate a
    # lone `--secret SLOT=REF` for a single named slot (parity with binding add).
    slots: tuple[str, ...] = ()
    label = a.provider
    if a.injector is not None:
        slots = find_injector(a.injector).spec.slots  # raises InjectorError
        label = f"{a.injector}-{a.provider}"

    secret = _parse_secret_args(a.secret, slots)
    if not a.provider or secret is None:
        fail("ad-hoc `binding test` needs --provider and --secret")

    find_provider(a.provider)  # raises ProviderError if it doesn't resolve

    probe = core_bindings.Binding(
        name=label, injector=a.injector or "", provider=a.provider,
        secret=secret, hosts=(), placeholder=None, env=None,
    )
    r = core_bindings.test_binding(probe)
    render.OUT.binding_test([{
        "name": label,
        "provider": a.provider,
        "ok": r.ok,
        "value_len": r.value_len,
        "error": r.error,
        "note": r.note,
    }])
    if not r.ok:
        sys.exit(1)


def _binding_subparsers(parent: argparse._SubParsersAction) -> None:
    p = parent.add_parser("add")
    # Single-binding path. Coordinated multi-binding sets + guardrails are the
    # `pack` noun's job (`workspace NAME pack add PACK`), not a flag here.
    p.add_argument("--injector", default=None)
    p.add_argument("--provider", default=None)
    # Repeatable: a single bare REF is single-slot; one or more `slot=ref`
    # values form a multi-slot secret table.
    p.add_argument("--secret", action="append", metavar="REF|SLOT=REF")
    # Repeatable. A literal hostname is matched exactly; a value containing `*`
    # is a glob (`*` spans dots), so `*.amazonaws.com` scopes one binding to
    # every AWS region/service endpoint. The two rightmost labels must be
    # literal (`*.example.com` ok; `*.com`/`*` rejected).
    p.add_argument("--host", action="append", metavar="HOST|GLOB")
    p.add_argument("--name", dest="binding_name", default=None)
    p.add_argument("--placeholder", default=None)
    # --env overrides the injector's suggested env; --no-env suppresses it
    # (writes `env = false`), so the placeholder is exposed under no env var.
    env_group = p.add_mutually_exclusive_group()
    env_group.add_argument("--env", default=None)
    env_group.add_argument("--no-env", action="store_true")

    p = parent.add_parser("remove")
    p.add_argument("binding_name", metavar="NAME")

    parent.add_parser("list")

    p = parent.add_parser("test")
    p.add_argument("binding_name", metavar="NAME", nargs="?", default=None)
    # Ad-hoc mode: test a definition before it is bound (no workspace needed).
    p.add_argument("--injector", default=None)
    p.add_argument("--provider", default=None)
    p.add_argument("--secret", action="append", metavar="REF|SLOT=REF")
