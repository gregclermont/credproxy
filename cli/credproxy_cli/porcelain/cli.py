"""The porcelain front-end: argument parsing, convenience resolution, and
rendering. Two surfaces over one core.

Surfaces (chosen purely by invocation, never by terminal sniffing):
  - STRICT (`credproxy`): every workspace named explicitly; omitting one is a
    clear error. No default-workspace resolution, no prompts ever, no aliases.
    The scriptable contract.
  - LOOSE (`credproxy --loose`, aliased `credp`): adds default-workspace
    resolution (announced on stderr), short command aliases that resolve to
    canonical commands with no independent behavior, and the confirmation gate
    on destructive-and-implicit actions.

`--json` is orthogonal to the surface: it selects the renderer only.

Grammar (canonical):
    credproxy workspace create NAME
    credproxy workspace use NAME
    credproxy workspace list [FILTER]
    credproxy list [FILTER]                       # canonical survey
    credproxy workspace NAME {enter|start|stop|recreate|delete|apply|inspect|logs}
    credproxy workspace NAME binding {add|remove|list|test} ...
    credproxy injector {scaffold NAME|list}
    credproxy provider {scaffold NAME|list}
    credproxy dev {build|test|reload}

argparse can't express name-before-verb, so the `workspace` noun is dispatched
by a small hand-rolled router (peek the second token: a verb routes directly,
anything else is a workspace name and the third token is the verb). Leaf
commands' flags still go through argparse.
"""
from __future__ import annotations

import argparse
import os
import sys

from ..core import dirmatch
from ..core import docker as core_docker
from ..core import lifecycle
from ..core import pointer
from ..core import workspace as core_workspace
from ..core.errors import CredproxyError
from ..core.workspace import RESERVED_NAMES, Workspace, for_name
from ..core.paths import (
    IMAGE_TAG,
    PROXY_DIR,
    TESTS_DIR,
)
from . import render
from .render import fail, say


# Workspace-scoped verbs (the `workspace NAME <verb>` tail).
_WS_VERBS = {
    "enter", "edit", "start", "stop", "recreate", "delete", "apply", "inspect",
    "config", "logs", "binding", "bind-dir", "mount", "rule",
}
# Workspace-level verbs that take a name as their argument, not a subject.
_WS_NOUN_VERBS = {"create", "use", "list"}
# Top-level meta commands: no workspace argument. Every token in the three
# command sets above and here must be in core's RESERVED_NAMES (a workspace
# can't take a colliding name) -- guarded by test_reserved_names_cover_all_cli_verbs.
_META_COMMANDS = {"list", "current", "info"}


# ---- a parsed invocation ----------------------------------------------------


class Ctx:
    """Resolved invocation context shared by every handler."""

    def __init__(self, loose: bool, as_json: bool, assume_yes: bool):
        self.loose = loose
        self.json = as_json
        self.assume_yes = assume_yes


def _resolve_ws(ctx: Ctx, name: str | None) -> Workspace:
    """Resolve an (optionally omitted) workspace name to a concrete Workspace.

    STRICT: a missing name is an error -- explicit naming is the contract.
    LOOSE: a missing name resolves by current directory first (a workspace whose
    `directory` is an ancestor of cwd), then the default pointer; either way the
    resolution is announced on stderr. cwd wins because "what I mean here" beats
    "what I usually mean"."""
    if name is not None:
        return for_name(name)
    if not ctx.loose:
        fail("workspace name required (strict mode names every workspace)")
    ws = dirmatch.resolve_cwd()
    if ws is not None:
        say(f"workspace: {ws.name} (matched current directory)")
        return ws
    ws = pointer.resolve_default()
    say(f"workspace: {ws.name} (default)")
    return ws


def _is_default(ws: Workspace) -> bool:
    return pointer.read_default() == ws.name


def _confirm_destructive(ctx: Ctx, ws: Workspace, implicit: bool, verb: str) -> None:
    """The safety gate. Fires only when a destructive command targets an
    IMPLICIT (defaulted or cwd-matched) workspace, in LOOSE mode. Explicit
    targets never prompt. `--yes` bypasses. Fails closed without a TTY."""
    if not (ctx.loose and implicit):
        return
    if ctx.assume_yes:
        return
    if not sys.stdin.isatty():
        fail(
            f"refusing to {verb} the implicitly-selected workspace '{ws.name}' "
            f"without confirmation: stdin is not a TTY (pass --yes)"
        )
    suffix = ("(current default)" if pointer.read_default() == ws.name
              else "(matched current directory)")
    # Prompt to STDERR (not via input(), which writes it to stdout and would
    # corrupt a --json stdout stream). EOF (closed stdin) reads "" -> abort.
    print(f'{verb.capitalize()} workspace "{ws.name}" {suffix}? [y/N] ',
          end="", file=sys.stderr, flush=True)
    reply = sys.stdin.readline()
    if reply.strip().lower() not in ("y", "yes"):
        fail("aborted")


def _confirm_running_recreate(ctx: Ctx, ws: Workspace, sessions: int) -> None:
    """Gate `mount add --preserve` when it would stop+recreate a RUNNING
    workspace that has live `enter` session(s) -- those sessions are killed by
    the recreate. Unlike _confirm_destructive, the trigger is runtime state (live
    sessions), not resolution mode, so it fires even for an explicit NAME.

    `--yes` bypasses. STRICT refuses (scriptable, never prompts -- a script must
    opt in with --yes). LOOSE prompts; fails closed without a TTY."""
    if ctx.assume_yes:
        return
    plural = "s" if sessions != 1 else ""
    msg = (f"workspace '{ws.name}' is running with {sessions} active "
           f"session{plural}; --preserve stops and recreates it "
           f"(those sessions are terminated)")
    if not ctx.loose:
        fail(f"{msg}. Re-run with --yes to proceed.")
    if not sys.stdin.isatty():
        fail(f"{msg}, and stdin is not a TTY. Re-run with --yes.")
    # Prompt to STDERR (input() would corrupt a --json stdout). EOF -> abort.
    print(f"{msg}. Continue? [y/N] ", end="", file=sys.stderr, flush=True)
    if sys.stdin.readline().strip().lower() not in ("y", "yes"):
        fail("aborted")


def _require_exists(ws: Workspace) -> None:
    if not ws.exists():
        fail(f"workspace '{ws.name}' not found")


# ---- workspace commands ------------------------------------------------------


def do_create(ctx: Ctx, name: str | None, directory: str | None = None) -> None:
    # Loose-surface convenience: an omitted NAME is derived from the --here/--dir
    # directory basename. Strict always names explicitly; with no directory there
    # is nothing to derive from.
    if name is None:
        if not ctx.loose:
            fail("workspace name required (strict surface names every workspace); "
                 "`credp create --here` derives one from the directory")
        if directory is None:
            fail("nothing to derive a name from: pass NAME, or --here/--dir")
        name = core_workspace.derive_workspace_name(directory)
        say(f"derived workspace name '{name}' from {directory}")
    ws = for_name(name)  # reserved-name / charset check happens here
    lifecycle.create_workspace_files(ws)
    render.OUT.created(ws.name, str(ws.config_path))
    # Optional cwd-association (`--here`/`--dir`): record the directory this
    # workspace is "for" so `credp <verb>` resolves it from there (dirmatch).
    if directory is not None:
        from ..core import config as core_config
        real = os.path.realpath(directory)
        if real == os.path.sep or real == os.path.realpath(os.path.expanduser("~")):
            say(f"note: {directory} is too broad -- cwd resolution ignores it")
        claimer = dirmatch.find_claimer(directory, exclude=ws.name)
        if claimer:
            say(f"note: directory {directory} is also claimed by '{claimer}'")
        core_config.associate_directory(ws, directory)
        say(f"associated with directory {directory}")
    # Loose convenience: seed the default-workspace pointer when it is unset,
    # so `credp enter` works immediately without a separate `use`. Only fills a
    # vacuum -- never overrides an existing selection -- and is announced. The
    # pointer is a loose-surface concept, so strict `create` never touches it.
    if ctx.loose and pointer.read_default() is None:
        pointer.set_default(ws)
        say(f"set '{ws.name}' as the default workspace")


def do_bind_dir(ctx: Ctx, name: str | None, directory_flag: str | None) -> None:
    """Associate a workspace with a host directory (default: cwd), so a loose
    `credp <verb>` run from at/under it resolves here. Sugar over editing the
    `directory` field; the TOML stays the source of truth."""
    from ..core import config as core_config

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    directory = (os.path.abspath(os.path.expanduser(directory_flag))
                 if directory_flag else os.getcwd())
    real = os.path.realpath(directory)
    if real == os.path.sep or real == os.path.realpath(os.path.expanduser("~")):
        say(f"note: {directory} is too broad -- cwd resolution ignores it")
    claimer = dirmatch.find_claimer(directory, exclude=ws.name)
    if claimer:
        say(f"note: directory {directory} is also claimed by '{claimer}'")
    core_config.associate_directory(ws, directory)
    render.OUT.bound_dir(ws.name, directory)


def do_use(ctx: Ctx, name: str) -> None:
    ws = for_name(name)
    pointer.set_default(ws)  # verifies existence
    render.OUT.used(ws.name)


def do_current(ctx: Ctx) -> None:
    """Report the workspace a bare verb targets, distinct from the default
    pointer. Loose-only (the strict surface has no implicit target). Mirrors
    `_resolve_ws`: cwd match first, then the default -- the source (and any
    shadowed default) are announced on stderr, so stdout stays just the name
    for `$(credp current)`."""
    default = pointer.read_default()
    try:
        here = dirmatch.resolve_cwd()
    except CredproxyError as e:
        # cwd is contested -> a bare verb errors here; say so, then fall back to
        # the default pointer for reference.
        say(str(e))
        render.OUT.current(default, "default" if default else None, default)
        return
    if here is not None:
        if default == here.name:
            say("current directory; also default")
        elif default:
            say(f"current directory; default is '{default}'")
        else:
            say("current directory (no default set)")
        render.OUT.current(here.name, "directory", default)
    elif default:
        say("default")
        render.OUT.current(default, "default", default)
    else:
        render.OUT.current(None, None, default)


def do_list(ctx: Ctx, filter_: str | None) -> None:
    from ..core import config as core_config

    # The default pointer and cwd matching are loose-only implicit-targeting
    # concepts; the strict surface is a plain inventory that consults neither
    # (so the `*`/`→` markers never appear there). The DIRECTORY column is
    # factual config and shows on both.
    default = pointer.read_default() if ctx.loose else None
    here_name = None
    if ctx.loose:
        # Which workspace (if any) cwd resolves to -- informational marker only.
        # Tolerate ambiguity (don't crash `list` over it).
        try:
            here_ws = dirmatch.resolve_cwd()
            here_name = here_ws.name if here_ws else None
        except CredproxyError:
            here_name = None
    rows = []
    for s in core_workspace.list_workspaces():
        if filter_ and filter_ not in s.name:
            continue
        rows.append({
            "name": s.name,
            "running": s.running,
            "image": s.image,
            "default": s.name == default,
            "directory": core_config.quick_directory(Workspace(s.name)),
            "here": s.name == here_name,
        })
    render.OUT.workspace_list(rows)


def do_info(ctx: Ctx) -> None:
    """Inspect the *centralized* (non-workspace) config and state: the default
    pointer, resolved roots (config/state/profile/builtin), the proxy image, the
    three-tier registry breakdown, and the env overrides in effect. The default
    workspace is a loose-only concept, so it appears only on the loose surface
    (consistent with `list`/`current`); everything else is surface-agnostic."""
    from collections import Counter
    from ..core import paths, presets as core_presets
    from ..core.injectors import list_injectors
    from ..core.providers import list_providers
    from ..core.scripts import list_scripts

    def tiers(counter: Counter) -> dict:
        return {t: counter.get(t, 0) for t in ("user", "profile", "builtin")}

    registries = {
        "injectors": tiers(Counter(i.source for i in list_injectors())),
        "providers": tiers(Counter(p.source for p in list_providers())),
        "scripts": tiers(Counter(s.source_origin for s in list_scripts())),
        "presets": tiers(Counter(core_presets.load_preset_sources().values())),
    }
    profile = paths.profile_dir()
    profile_present = profile.is_dir()
    # "overrides" = registry definitions resolving from the profile tier, plus a
    # profile-supplied workspace.template.toml -- what the overlay actually adds.
    profile_overrides = sum(r["profile"] for r in registries.values()) + (
        1 if (profile / "workspace.template.toml").is_file() else 0)

    data: dict = {}
    if ctx.loose:  # the default pointer is a loose-only concept
        data["default_workspace"] = pointer.read_default()
    data["workspaces"] = len(core_workspace.list_names())
    data["paths"] = {
        "config": str(paths.config_dir()),
        "state": str(paths.state_dir()),
        "profile": str(profile),
        "profile_present": profile_present,
        "builtin": str(paths.BUILTIN_DIR),
    }
    data["proxy_image"] = paths.IMAGE_TAG
    data["profile_overrides"] = profile_overrides
    data["registries"] = registries
    data["env"] = {
        "XDG_CONFIG_HOME": os.environ.get("XDG_CONFIG_HOME"),
        "XDG_STATE_HOME": os.environ.get("XDG_STATE_HOME"),
        "CREDPROXY_PROFILE_DIR": os.environ.get("CREDPROXY_PROFILE_DIR"),
        "EDITOR": os.environ.get("VISUAL") or os.environ.get("EDITOR"),
    }
    render.OUT.info(data)


def do_enter(ctx: Ctx, name: str | None, trailing: list[str],
             user_override: str | None = None, push: bool = False) -> None:
    if ctx.json:
        fail("enter does not support --json (it execs an interactive shell)")
    ws = _resolve_ws(ctx, name)
    # Empty trailing -> the core runs the config `shell` (default: a login
    # shell); an explicit `-- CMD` runs bare. Resolved in _enter_exec_cmd, which
    # has the loaded config.
    exit_code = lifecycle.enter_workspace(
        ws, trailing, notify=say, user_override=user_override, push=push)
    sys.exit(exit_code)


def do_edit(ctx: Ctx, name: str | None) -> None:
    """Open the workspace's config file in $EDITOR, then validate it. The file
    is the source of truth; this is sugar over editing it directly."""
    import shlex
    import subprocess

    if ctx.json:
        fail("edit does not support --json (it opens an interactive editor)")
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    cmd = shlex.split(editor) + [str(ws.config_path)]
    try:
        rc = subprocess.run(cmd).returncode
    except FileNotFoundError:
        fail(f"could not launch editor '{editor}' (set $EDITOR or $VISUAL)")
    if rc != 0:
        fail(f"editor exited with status {rc}; config left as-is")

    # Post-edit validation: report problems but never revert -- it's the
    # user's file. load_config/load_bindings/load_rules parse and validate
    # without writing; `[[rule]]` is part of the file this edits, so validate it.
    from ..core import bindings as core_bindings
    from ..core import config as core_config
    from ..core import rules as core_rules
    try:
        core_config.load_config(ws)
        core_bindings.load_bindings(ws)
        core_rules.load_rules(ws)
    except CredproxyError as e:
        say(f"warning: config is invalid — {e}")
        say("fix it before `start`/`apply`, or the workspace won't update cleanly.")
        return
    say("edited. changes are not live yet: `apply` (bindings) or "
        "`start` (image/home/mounts/env/setup).")


def do_start(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    lifecycle.start_workspace(ws, notify=say)
    render.OUT.started(ws.name)


def do_stop(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    lifecycle.stop_workspace(ws)
    render.OUT.stopped(ws.name)


def do_delete(ctx: Ctx, name: str | None, keep_volumes: bool) -> None:
    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "delete")
    was_default = _is_default(ws)
    lifecycle.delete_workspace(ws, keep_volumes=keep_volumes)
    if was_default:
        pointer.clear_default()
    render.OUT.deleted(ws.name)


def do_apply(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    result = lifecycle.apply_config(ws, notify=say)
    render.OUT.applied(ws.name, result)


def do_recreate(ctx: Ctx, name: str | None, include_proxy: bool,
                reset_volumes: list[str]) -> None:
    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Plain recreate keeps all persistent state, so it isn't gated. --reset-volume
    # wipes a volume's data (the one recreate mode that destroys data), so it is
    # gated like delete: confirm on an implicit default workspace (loose surface).
    if reset_volumes:
        _confirm_destructive(ctx, ws, implicit, "reset volume(s) of")
    lifecycle.recreate_workspace(ws, notify=say, include_proxy=include_proxy,
                                 reset_volumes=reset_volumes)
    render.OUT.recreated(ws.name, include_proxy, reset_volumes)


def do_config(ctx: Ctx, name: str | None, declared: bool) -> None:
    """Dump a workspace's container-side config. Default mode is `effective` --
    every field with its in-effect value, all defaults filled (the workspaceFolder
    `workdir`, the enter shim, etc.) -- so you can see what actually applies
    without it being in the file. `--declared` shows only what's literally in the
    TOML, before defaults."""
    from ..core import config as core_config
    ws = _resolve_ws(ctx, name)
    if declared:
        cfg = core_config.declared_config(ws)
    else:
        cfg = lifecycle.effective_config(core_config.load_config(ws))
    render.OUT.config({
        "mode": "declared" if declared else "effective",
        "config_path": str(ws.config_path),
        "config": cfg,
    })


def do_inspect(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    data = lifecycle.inspect_workspace(ws)
    render.OUT.inspect({
        "name": data.name,
        "config_path": data.config_path,
        "config": data.config,
        "proxy_status": data.proxy_status,
        "ws_status": data.ws_status,
        "running": data.running,
        "host_port": data.host_port,
        "bindings": [
            {
                "name": b.name,
                "injector": b.injector,
                "provider": b.provider,
                "secret": b.secret,
                "hosts": list(b.hosts),
                "placeholder": b.placeholder,
                "env": b.env,
            }
            for b in data.bindings
        ],
        "rules": [
            {
                "name": r.name,
                "hosts": list(r.hosts),
                "methods": list(r.methods) if r.methods else None,
                "path": r.path,
                "action": r.action,
                "visible": r.effective_visible,
                "script": r.script,
            }
            for r in data.rules
        ],
        "drift": {
            "in_sync": data.drift.in_sync,
            "changes": [
                {
                    "kind": c.kind,
                    "item": c.item,
                    "applied": c.applied,
                    "configured": c.configured,
                }
                for c in data.drift.changes
            ],
        },
        # Context for drift label: stopped workspace means bindings in
        # applied-bindings.json were "last applied" not "live".
        "_running": data.running,
    })


def do_logs(ctx: Ctx, name: str | None, audit: bool = False) -> None:
    ws = _resolve_ws(ctx, name)
    _logs_stream(ws, as_json=ctx.json, audit_only=audit)


# The proxy prefixes every structured record with this (see proxy/log.py).
_LOG_PREFIX = "credproxy "


def _parse_credproxy_line(line: str) -> dict | None:
    """Parse one `docker logs` line into a proxy structured record, or None if it
    isn't one. Requires the `credproxy ` prefix at the START of the line (not
    anywhere in it) plus a JSON object carrying a `kind`. Because the proxy
    JSON-encodes every untrusted value (a rule/scheme error message that can echo
    workspace input), such content is escaped inside the record and can NEVER
    spill a forged `credproxy {...}` line of its own -- the substring-forgery the
    old text stream allowed is structurally impossible."""
    import json
    if not line.startswith(_LOG_PREFIX):
        return None
    try:
        rec = json.loads(line[len(_LOG_PREFIX):])
    except json.JSONDecodeError:
        return None
    return rec if isinstance(rec, dict) and "kind" in rec else None


def _logs_stream(ws: Workspace, as_json: bool, audit_only: bool) -> None:
    """Tail `docker logs -f` and reformat the proxy's structured `credproxy {json}`
    records; mitmproxy's own termlog passes through verbatim (never mistaken for
    a proxy record). Default: pretty one line per record. `--json`: the raw
    records as JSON-lines (a non-proxy line wraps as `{"kind":"raw","line":...}`).
    `--audit`: only `kind == "audit"` records. docker's log driver is the durable
    store (survives stop/start)."""
    import json
    import subprocess

    proc = subprocess.Popen(
        ["docker", "logs", "-f", ws.proxy_container],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    interrupted = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            rec = _parse_credproxy_line(line)
            if audit_only:
                if rec is not None and rec.get("kind") == "audit":
                    print(json.dumps(rec) if as_json else _format_record(rec),
                          flush=True)
            elif rec is not None:
                print(json.dumps(rec) if as_json else _format_record(rec),
                      flush=True)
            elif as_json:      # non-proxy line (mitmproxy etc.)
                print(json.dumps({"kind": "raw", "line": line.rstrip("\n")}),
                      flush=True)
            else:
                print(line, end="", flush=True)   # pass mitmproxy output through
    except KeyboardInterrupt:
        interrupted = True
    finally:
        proc.terminate()
        rc = proc.wait()
    # A non-zero exit we didn't cause (Ctrl-C) is a real failure -- e.g. the
    # container doesn't exist; propagate it rather than reporting success.
    if not interrupted and rc:
        fail(f"docker logs exited with status {rc}")


def _format_record(rec: dict) -> str:
    """One-line human rendering of a proxy structured record (log.py). Tolerant of
    missing keys and unknown/future kinds."""
    ts = rec.get("ts", "")
    kind = rec.get("kind", "?")
    where = f"{rec.get('method', '')} {rec.get('host', '')}" \
            f"{rec.get('path', '')}".strip()
    if kind == "audit":
        subj = rec.get("binding") or rec.get("rule") or ""
        detail = " ".join(p for p in (subj and f"'{subj}'", rec.get("outcome", ""))
                          if p)
        return f"{ts}  audit {rec.get('event', '?'):<9} {where}  {detail}".rstrip()
    if kind in ("http", "api"):
        marks = rec.get("marks")
        return f"{ts}  {kind:<6} {where}" \
               f"{' (' + ' '.join(marks) + ')' if marks else ''}".rstrip()
    if kind == "sni":
        err = f" -- {rec['error']}" if rec.get("error") else ""
        return f"{ts}  sni    {rec.get('sni') or '<no-sni>'} " \
               f"({rec.get('decision', '?')}){err}"
    if kind == "rule-error":
        return f"{ts}  rule   {rec.get('rule', '')} failed: {rec.get('error', '')}"
    if kind in ("scheme", "script"):
        detail = rec.get("error") or rec.get("reason", "")
        return f"{ts}  {kind:<6} {rec.get('scheme', '')} " \
               f"{rec.get('phase') or rec.get('hook', '')}: {detail}".rstrip(": ")
    rest = " ".join(f"{k}={v}" for k, v in rec.items() if k not in ("ts", "kind"))
    return f"{ts}  {kind:<6} {rest}".rstrip()


# ---- binding commands --------------------------------------------------------


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


def do_binding_add(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core import bindings as core_bindings
    from ..core.bindings import Binding
    from ..core.injectors import find_injector
    from ..core.providers import find_provider

    if (a.preset is None) == (a.injector is None):
        fail("`binding add` needs exactly one of --preset or --injector")
    if a.preset is not None:
        _do_binding_preset(ctx, name, a)
        return

    if not a.host:
        fail("`binding add --injector` needs at least one --host")

    if not a.provider:
        fail("`binding add --injector` needs --provider")

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    injector = find_injector(a.injector)
    find_provider(a.provider)

    # Parse --secret with the injector's declared slots, so a lone
    # `--secret SLOT=REF` for a single named slot (e.g. jwt-bearer's
    # private_key) is recognized rather than swallowed as a bare `value` ref.
    secret = _parse_secret_args(a.secret, injector.spec.slots)
    if secret is None:
        fail("`binding add` needs --secret")

    # Lock the read-validate-write: two concurrent `binding add` must not both
    # read the same file, pick the same auto-name, and last-writer-wins (the
    # per-file atomic write prevents a torn file, not a lost update).
    with ws.lock():
        existing = core_bindings.load_bindings(ws)
        taken = {b.name for b in existing}
        bname = a.binding_name or core_bindings._auto_name(a.injector, a.provider, taken)
        if bname in taken:
            fail(f"binding name '{bname}' already exists in workspace '{ws.name}'")

        # Sign schemes (sigv4, ...) hold no inert placeholder; only substitute
        # schemes do, and only those get one auto-generated.
        if injector.spec.uses_placeholder:
            placeholder = a.placeholder or injector.placeholder.generate()
        else:
            placeholder = a.placeholder
        env = a.env or injector.env

        binding = Binding(
            name=bname,
            injector=a.injector,
            provider=a.provider,
            secret=secret,
            hosts=tuple(a.host),
            placeholder=placeholder,
            env=env,
        )
        core_bindings.validate(existing + [binding], str(ws.config_path))
        core_bindings.append_binding(ws, binding)

    render.OUT.binding_added(bname, ws.name, {
        "name": bname,
        "injector": binding.injector,
        "provider": binding.provider,
        "secret": binding.secret,
        "hosts": list(binding.hosts),
        "placeholder": placeholder,
        "env": env,
    })


def _do_binding_preset(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    """Generate a coordinated binding set from a preset (e.g. github) and
    append all of them, sharing one placeholder."""
    from ..core import bindings as core_bindings
    from ..core.presets import build_preset, load_presets
    from ..core.providers import find_provider

    if a.binding_name or a.placeholder or a.env or a.host:
        fail("--preset manages name/placeholder/env/host itself; drop those flags")

    presets = load_presets()
    spec = presets.get(a.preset)
    if spec is None:
        fail(f"unknown preset '{a.preset}'; known presets: "
             f"{', '.join(sorted(presets)) or '(none)'}")

    # Provider: the explicit flag, else the preset's default.
    provider = a.provider or spec.default_provider
    if provider is None:
        fail("`binding add --preset` needs --provider "
             "(this preset has no default provider)")

    # Secret: the explicit flag, else the preset's default -- but that default
    # ref is only meaningful for the provider it was written for (a ref is a gh
    # hostname for gh-cli, an env-var name for env, an op:// path for op), so any
    # other provider must still pass --secret.
    secret = _parse_secret_args(a.secret)
    if secret is None:
        if provider == spec.default_provider and spec.default_secret is not None:
            secret = spec.default_secret
        else:
            fail("`binding add --preset` needs --secret "
                 "(its meaning depends on --provider)")
    elif not isinstance(secret, str):
        fail("`binding add --preset` needs a single --secret REF")
    find_provider(provider)

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    with ws.lock():                          # atomic read-validate-write (see do_binding_add)
        existing = core_bindings.load_bindings(ws)
        taken = {b.name for b in existing}
        new = build_preset(a.preset, provider, secret)
        for b in new:
            if b.name in taken:
                fail(f"binding name '{b.name}' already exists in workspace '{ws.name}'")
        core_bindings.validate(existing + new, str(ws.config_path))
        core_bindings.append_bindings(ws, new)   # one atomic write
    # A preset expands to several bindings; say so up front (stderr) so the
    # human lines that follow aren't a surprise. Emit the result as ONE value
    # (render.OUT.bindings_added) so --json yields a single JSON object, not one
    # per binding (this is a one-shot command, not the JSON-lines `logs` stream).
    say(f"preset '{a.preset}' expands to {len(new)} bindings:")
    render.OUT.bindings_added(ws.name, [{
        "name": b.name,
        "injector": b.injector,
        "provider": b.provider,
        "secret": b.secret,
        "hosts": list(b.hosts),
        "placeholder": b.placeholder,
        "env": b.env,
    } for b in new])


def do_binding_remove(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core import bindings as core_bindings

    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "remove binding from")
    with ws.lock():                          # atomic read-modify-write of the TOML
        core_bindings.remove_binding(ws, a.binding_name)
    render.OUT.binding_removed(a.binding_name, ws.name)


def do_binding_list(ctx: Ctx, name: str | None) -> None:
    from ..core import bindings as core_bindings

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Hold the lock: materialize may write back generated names/placeholders, so
    # a concurrent add/remove must not race this read-modify-write.
    with ws.lock():
        bindings = core_bindings.materialize_bindings(ws, notify=say)
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
    from ..core import bindings as core_bindings

    # Ad-hoc mode: `binding test --provider P --secret REF [--injector I]`
    # exercises a definition before it is bound -- no workspace involved.
    if a.injector is not None or a.provider is not None or a.secret is not None:
        _do_binding_test_adhoc(ctx, name, a)
        return

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Hold the lock only for the materializing read-modify-write; the provider
    # fetch below needs no lock (and can be slow).
    with ws.lock():
        bindings = core_bindings.materialize_bindings(ws, notify=say)
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
    from ..core import bindings as core_bindings
    from ..core.injectors import find_injector
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


# ---- rule commands -----------------------------------------------------------


def _parse_kv(values: list[str] | None, flag: str) -> dict | None:
    """Parse repeated `K=V` flags into a dict (order-preserving). None if unset."""
    if not values:
        return None
    out: dict[str, str] = {}
    for v in values:
        key, sep, val = v.partition("=")
        if not sep or not key:
            fail(f"{flag} '{v}' must be K=V")
        out[key] = val
    return out


def _rule_row(rule) -> dict:
    """Workspace-safe rule summary for rendering (no secret -- rules have none)."""
    return {
        "name": rule.name,
        "hosts": list(rule.hosts),
        "methods": list(rule.methods) if rule.methods else None,
        "path": rule.path,
        "action": rule.action,
        "visible": rule.effective_visible,
        "script": rule.script,
        "status": rule.status,
    }


def do_rule_add(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from dataclasses import replace as _replace

    from ..core import rules as core_rules

    action = a.rule_action                   # the subcommand: block/respond/rewrite/script
    if not a.host:
        fail("`rule add` needs at least one --host")

    # Each action's subparser owns exactly its own flags (argparse rejects the
    # rest), so we just marshal the flags that are present into the `[[rule]]`
    # entry shape and route it through the ONE field validator (_parse_rule_entry)
    # -- the same one the load path uses. Missing/malformed action params (a
    # respond without --status, an empty rewrite) fail there, uniformly.
    entry: dict = {"action": action, "hosts": list(a.host)}
    if a.method:
        entry["methods"] = list(a.method)
    if a.path is not None:
        entry["path"] = a.path
    if a.rule_visible is not None:
        entry["visible"] = a.rule_visible
    if action == "block":
        if a.status is not None:
            entry["status"] = a.status
    elif action == "respond":
        if a.status is not None:
            entry["status"] = a.status       # _parse_rule_entry requires it
        if a.body is not None:
            entry["body"] = a.body
        if a.header:
            entry["headers"] = _parse_kv(a.header, "--header")
    elif action == "rewrite":
        if a.header:
            entry["set_headers"] = _parse_kv(a.header, "--header")
        if a.remove_header:
            entry["remove_headers"] = list(a.remove_header)
        if a.resp_header:
            entry["resp_set_headers"] = _parse_kv(a.resp_header, "--resp-header")
        if a.resp_remove_header:
            entry["resp_remove_headers"] = list(a.resp_remove_header)
    elif action == "script":
        if a.script is not None:
            entry["script"] = a.script

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    with ws.lock():                          # atomic read-validate-write
        existing = core_rules.load_rules(ws)
        taken = {r.name for r in existing}
        if a.rule_name:
            entry["name"] = a.rule_name
        rule = core_rules._parse_rule_entry(entry, str(ws.config_path), "rule add")
        if rule.name is None:
            rule = _replace(rule, name=core_rules._auto_name(rule, taken))
        if rule.name in taken:
            fail(f"rule name '{rule.name}' already exists in workspace '{ws.name}'")
        core_rules.validate(existing + [rule], str(ws.config_path))
        core_rules.append_rule(ws, rule)

    render.OUT.rule_added(rule.name, ws.name, _rule_row(rule))


def do_rule_remove(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core import rules as core_rules

    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "remove rule from")
    with ws.lock():
        core_rules.remove_rule(ws, a.rule_name)
    render.OUT.rule_removed(a.rule_name, ws.name)


def do_rule_list(ctx: Ctx, name: str | None) -> None:
    from ..core import rules as core_rules

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    # Hold the lock: materialize may write back generated names, so a concurrent
    # add/remove must not race this read-modify-write.
    with ws.lock():
        rules = core_rules.materialize_rules(ws, notify=say)
    render.OUT.rule_list(ws.name, [_rule_row(r) for r in rules])


def do_rule_test(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from urllib.parse import urlsplit

    from ..core import rules as core_rules

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    if getattr(a, "rule_live", False):
        _do_rule_test_live(ctx, ws, a)
        return

    parts = urlsplit(a.url)
    host = parts.hostname
    if not host:
        fail(f"'{a.url}' has no host (use a full URL, e.g. https://api.github.com/x)")
    path = parts.path or "/"
    # Hold the lock only for the materializing read-modify-write.
    with ws.lock():
        rules = core_rules.materialize_rules(ws, notify=say)
    matches = core_rules.match_rules(rules, a.method, host, path)
    # Enrich each match with the rule's action detail (status/script) for display.
    by_name = {r.name: r for r in rules}
    rows = []
    for m in matches:
        r = by_name[m.name]
        rows.append({"name": m.name, "action": m.action, "visible": m.visible,
                     "script": r.script, "status": r.status,
                     "terminal": m.terminal, "may_terminate": m.may_terminate,
                     "conditional": m.conditional})
    render.OUT.rule_test(a.method.upper(), a.url, rows)


def _do_rule_test_live(ctx: Ctx, ws: Workspace, a: argparse.Namespace) -> None:
    """`rule test --live`: ask the RUNNING proxy for the authoritative answer
    (exact per-script phase + intercept decision) against its LOADED config --
    which may lag the edited TOML until `apply`/`start`."""
    from ..core import proxy_http
    from ..core.imageenv import ImageEnv

    if core_docker.container_status(ws.proxy_container) != "running":
        fail(f"workspace '{ws.name}' proxy is not running; `start` it, or omit "
             f"--live for the offline (config-file) dry-run")
    meta = ImageEnv.load()
    host_port = core_docker.resolve_host_port(ws.proxy_container, meta.http_port)
    result = proxy_http.rule_test_live(ws, host_port, a.method, a.url)
    render.OUT.rule_test_live(a.method.upper(), a.url, result)


# ---- mount commands ----------------------------------------------------------


def do_mount_add(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    """Add a managed-volume mount to a workspace. `--preserve` first captures the
    live container's data at --target into the new volume, then recreates so the
    volume mounts populated (otherwise the change is deferred to the next
    `start`, with the volume image-seeded as usual)."""
    if not a.mount_volume:
        fail("`mount add` needs --volume NAME")
    if not a.mount_target:
        fail("`mount add` needs --target PATH")

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    # Gate only the disruptive path: --preserve restarts the container, killing
    # any live `enter` sessions. A plain add is a deferred config edit, like
    # editing the file, so it isn't gated (mirrors un-gated plain `recreate`).
    if a.mount_preserve:
        status = core_docker.container_status(ws.ws_container)
        sessions = (lifecycle._count_live_sessions(ws)
                    if status == "running" else 0)
        if sessions:
            _confirm_running_recreate(ctx, ws, sessions)

    lifecycle.add_managed_volume(
        ws, name=a.mount_volume, target=a.mount_target,
        readonly=a.mount_ro, preserve=a.mount_preserve,
        user_owned=a.mount_user_owned, notify=say,
    )
    render.OUT.mount_added(ws.name, a.mount_volume, a.mount_target,
                           a.mount_ro, applied=a.mount_preserve)


# ---- injector / provider -----------------------------------------------------


def do_scaffold(ctx: Ctx, kind: str, name: str, lang: str = "python") -> None:
    from ..core.scaffold import scaffold

    result = scaffold(kind, name, lang)
    render.OUT.scaffolded(result.kind, result.name, str(result.path))
    if kind == "provider":
        say("the template is just a starting point -- a provider can be any "
            "executable that speaks the JSON protocol (docs/providers.md).")


def do_def_list(ctx: Ctx, kind: str) -> None:
    if kind == "injector":
        from ..core.injectors import list_injectors
        rows = [
            {
                "name": d.name,
                "scheme": d.scheme if d.scheme != "script"
                else f"script:{d.spec.family}",
                "source": d.source,
            }
            for d in list_injectors()
        ]
    else:
        from ..core.providers import list_providers
        rows = [
            {"name": d.name, "source": d.source, "description": d.description or ""}
            for d in list_providers()
        ]
    render.OUT.def_list(kind, rows)


def do_preset_list(ctx: Ctx) -> None:
    from ..core.presets import describe_presets

    render.OUT.preset_list(describe_presets())


def do_provider_show(ctx: Ctx, name: str) -> None:
    from ..core.providers import find_provider, _describe, _help

    p = find_provider(name)  # raises ProviderError if missing / not executable
    render.OUT.provider_show({
        "name": p.name,
        "source": p.source,
        "path": str(p.exe),
        "description": _describe(p.exe),
        "help": _help(p.exe),
    })


# ---- dev harness -------------------------------------------------------------


def do_dev_build(ctx: Ctx) -> None:
    if not PROXY_DIR.is_dir():
        fail(f"{PROXY_DIR} not found -- `dev` commands need the repo checkout")

    core_docker.docker(["build", "-t", IMAGE_TAG, str(PROXY_DIR)], stream=True)


def do_dev_test(ctx: Ctx, trailing: list[str], cli_only: bool = False,
                proxy_only: bool = False, force_container: bool = False) -> None:
    """Run the test suite(s).

    Default: run BOTH the host-side CLI tests (tests/cli/) and the proxy suite
    (tests/). The proxy suite runs ON-HOST when its runtime deps (mitmproxy,
    aiohttp, starlark) import there -- near-instant -- else inside the image via
    `docker run`. Trailing args after `--` pass through to the proxy pytest.

    --cli:       host CLI tests only (no docker required).
    --proxy:     proxy suite only.
    --container: force the proxy suite into the image even if the deps are
                 importable on the host (the canonical, version-pinned env).
    """
    import importlib.util
    import subprocess
    from ..core.imageenv import ImageEnv
    from ..core.paths import TESTS_DIR, REPO_ROOT

    run_cli = not proxy_only
    run_proxy = not cli_only

    cli_failed = False
    if run_cli:
        if importlib.util.find_spec("pytest") is None:
            # Graceful note rather than a raw "No module named pytest".
            msg = ("host pytest not found; skipping CLI tests "
                   "(install pytest to run tests/cli/)")
            if not run_proxy:
                fail(msg)
            say(msg)
        else:
            say("running host-side CLI tests (tests/cli/)...")
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(REPO_ROOT / "tests" / "cli"), "-v"],
                check=False,
            )
            cli_failed = result.returncode != 0
            say("CLI tests FAILED" if cli_failed else "CLI tests passed.")
            if not run_proxy:
                sys.exit(result.returncode)

    # Proxy suite. tests/cli/ is excluded (host-only; its module names collide
    # with the proxy suite's under one rootdir). Prefer running it ON-HOST when
    # the proxy's runtime deps import there -- it skips the ~container-startup
    # tax that dominates the inner loop -- falling back to the image otherwise.
    proxy_deps = ("mitmproxy", "aiohttp", "starlark")
    missing = [m for m in proxy_deps if importlib.util.find_spec(m) is None]
    if not force_container and not missing:
        say("running proxy suite on-host (deps present; --container forces the image)...")
        env = {**os.environ, "PYTHONPATH": str(PROXY_DIR)}
        host_cmd = [sys.executable, "-m", "pytest", "-v", str(TESTS_DIR),
                    "--ignore", str(TESTS_DIR / "cli")] + trailing
        if cli_failed:
            r = subprocess.run(host_cmd, check=False, env=env)
            sys.exit(1 if r.returncode == 0 else r.returncode)
        os.execvpe(sys.executable, host_cmd, env)  # replace proc; preserves TTY

    if not force_container:
        say(f"proxy deps not importable on host ({', '.join(missing)}); running the "
            f"proxy suite in the image. Install them (see proxy/requirements.txt) "
            f"for the faster on-host path.")
    meta = ImageEnv.load()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{PROXY_DIR}:{meta.source}",
        "-v", f"{TESTS_DIR}:/opt/tests",
        # Read-only so the proxy suite can validate the CLI's builtin scripts
        # (the dogfood .star) against the Python built-ins -- single source of
        # truth, even though the proxy never reads cli/ at runtime.
        "-v", f"{REPO_ROOT / 'cli'}:/opt/cli:ro",
        "-w", "/opt",
        "--entrypoint", "python",
        IMAGE_TAG,
        "-m", "pytest", "-v", "tests/", "--ignore=tests/cli",
    ]
    cmd += trailing
    if cli_failed:
        # Run via subprocess so the final exit reflects the combined result.
        r = subprocess.run(cmd, check=False)
        sys.exit(1 if r.returncode == 0 else r.returncode)
    # Happy path or proxy-only: exec into docker (preserves TTY).
    os.execvp("docker", cmd)


def do_dev_reload(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    lifecycle.reload_proxy(ws)
    render.OUT.reloaded(ws.name)


# ---- argparse leaf parsers ---------------------------------------------------
#
# argparse handles each leaf command's flags. The dispatcher feeds it a
# normalized argv (canonicalized so name-before-verb and aliases collapse to a
# single internal form: `_ws <verb> [NAME] ...`).


def _binding_subparsers(parent: argparse._SubParsersAction) -> None:
    p = parent.add_parser("add")
    # --preset generates a coordinated binding set (e.g. github); --injector is
    # the single-binding path. Exactly one is required (checked in the handler,
    # so the error is a friendly message rather than argparse usage spew).
    p.add_argument("--preset", default=None)
    p.add_argument("--injector", default=None)
    # Optional at the parser level: required with --injector, but a preset may
    # supply a default provider (e.g. github -> gh-cli). Enforced in the handler.
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
    p.add_argument("--env", default=None)

    p = parent.add_parser("remove")
    p.add_argument("binding_name", metavar="NAME")

    parent.add_parser("list")

    p = parent.add_parser("test")
    p.add_argument("binding_name", metavar="NAME", nargs="?", default=None)
    # Ad-hoc mode: test a definition before it is bound (no workspace needed).
    p.add_argument("--injector", default=None)
    p.add_argument("--provider", default=None)
    p.add_argument("--secret", action="append", metavar="REF|SLOT=REF")


def _rule_subparsers(parent: argparse._SubParsersAction) -> None:
    add = parent.add_parser("add")
    # The action is a SUBCOMMAND (`rule add block|respond|rewrite|script`), not a
    # `--action` flag, so each action's parser owns exactly its own params and
    # argparse rejects an out-of-action flag structurally -- no hand-rolled
    # rejection table. The scoping flags common to every action live on a shared
    # parent parser mixed into each via `parents=`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", action="append", metavar="HOST|GLOB", dest="host",
                        help="literal or glob (`*.amazonaws.com`); repeatable")
    common.add_argument("--method", action="append", metavar="METHOD", dest="method",
                        help="restrict to these methods (repeatable; default all)")
    common.add_argument("--path", default=None, metavar="GLOB",
                        help="path glob: * within a segment, ** across (e.g. /repos/**)")
    common.add_argument("--name", dest="rule_name", default=None,
                        help="rule name (auto-generated if omitted)")
    common.add_argument("--visible", dest="rule_visible", action="store_true",
                        default=None, help="force enumerated + attributed")
    common.add_argument("--hidden", dest="rule_visible", action="store_false",
                        default=None, help="force unenumerated + unattributed")
    asub = add.add_subparsers(dest="rule_action", required=True,
                              metavar="{block,respond,rewrite,script}")

    pb = asub.add_parser("block", parents=[common])
    pb.add_argument("--status", type=int, default=None, help="refuse status (default 403)")

    pr = asub.add_parser("respond", parents=[common])
    pr.add_argument("--status", type=int, default=None, help="response status (required)")
    pr.add_argument("--body", default=None, help="response body")
    pr.add_argument("--header", action="append", metavar="K=V", dest="header",
                    help="a response header (repeatable)")

    pw = asub.add_parser("rewrite", parents=[common])
    pw.add_argument("--header", action="append", metavar="K=V", dest="header",
                    help="set a request header (repeatable)")
    pw.add_argument("--remove-header", action="append", metavar="NAME",
                    dest="remove_header", help="remove a request header")
    pw.add_argument("--resp-header", action="append", metavar="K=V",
                    dest="resp_header", help="set a response header")
    pw.add_argument("--resp-remove-header", action="append", metavar="NAME",
                    dest="resp_remove_header", help="remove a response header")

    ps = asub.add_parser("script", parents=[common])
    ps.add_argument("--script", default=None, metavar="NAME",
                    help="the .star rule script name")

    p = parent.add_parser("remove")
    p.add_argument("rule_name", metavar="NAME")

    parent.add_parser("list")

    p = parent.add_parser("test")
    p.add_argument("method", metavar="METHOD")
    p.add_argument("url", metavar="URL")
    p.add_argument("--live", action="store_true", dest="rule_live",
                   help="ask the RUNNING proxy for the authoritative answer "
                        "(exact script phase) against its loaded config, instead "
                        "of the offline config-file dry-run")


def _mount_subparsers(parent: argparse._SubParsersAction) -> None:
    p = parent.add_parser("add")
    p.add_argument("--volume", dest="mount_volume", default=None, metavar="NAME")
    p.add_argument("--target", dest="mount_target", default=None, metavar="PATH")
    p.add_argument("--ro", dest="mount_ro", action="store_true")
    # Seed the new volume with the current container's data at --target before
    # the recreate that applies the mount (otherwise the volume starts empty /
    # image-seeded). Requires an existing container to copy from.
    p.add_argument("--preserve", dest="mount_preserve", action="store_true")
    # Chown the volume to the workspace `user` after setup, so a non-root user
    # can write a volume mounted at an image-absent path (otherwise root-owned).
    p.add_argument("--user-owned", dest="mount_user_owned", action="store_true")


class _LeafParser(argparse.ArgumentParser):
    """ArgumentParser whose `error` routes through the porcelain renderer, so a
    bad/unknown/missing arg serializes as a JSON error object under --json (and a
    clean `[credproxy] ` line otherwise) and exits non-zero -- instead of
    argparse's raw usage dump to stderr + SystemExit(2), which bypassed the
    renderer entirely. Sub-parsers inherit this class (argparse defaults
    parser_class to type(self)), so the whole verb tree is covered."""

    def error(self, message: str):  # noqa: D401 - argparse hook
        fail(f"{self.prog}: {message}")


def _build_leaf_parser() -> argparse.ArgumentParser:
    """Parser for the verb tail of a workspace-scoped command. The dispatcher
    has already stripped `workspace` and the workspace name; what remains is
    `<verb> [args]`. NAME is threaded separately (resolved by the dispatcher)."""
    parser = _LeafParser(prog="credproxy workspace", add_help=False)
    sub = parser.add_subparsers(dest="verb", required=True)

    p_enter = sub.add_parser("enter")
    # One-session override of the config `user` (e.g. `enter --user root` for a
    # debug shell in a non-root workspace) without editing the config file.
    p_enter.add_argument("--user", dest="enter_user", default=None)
    # Force a config re-push (re-resolve secrets) even if the proxy already has
    # the current config -- e.g. after rotating a secret in place. Default skips
    # the push when the proxy's config fingerprint already matches.
    p_enter.add_argument("--push", dest="enter_push", action="store_true")
    sub.add_parser("edit")
    sub.add_parser("start")
    sub.add_parser("stop")
    p_recreate = sub.add_parser("recreate")
    # Default rebuilds only the workspace container (keeps the running proxy +
    # its CA). `--proxy`/`--all` also recreates the proxy (full re-bootstrap).
    p_recreate.add_argument("--proxy", "--all", dest="recreate_proxy",
                            action="store_true")
    # Also wipe the named managed volume(s) (re-seeded from the image), e.g.
    # `--reset-volume home`. Repeatable. Destroys data, so it's gated like
    # delete; bind/profile (host-path) mounts are untouched.
    p_recreate.add_argument("--reset-volume", dest="recreate_reset_volumes",
                            action="append", metavar="NAME", default=[])
    p_delete = sub.add_parser("delete")
    # Keep the workspace's managed volumes instead of wiping them (they become
    # orphans unless a same-named workspace is recreated).
    p_delete.add_argument("--keep-volumes", dest="delete_keep_volumes",
                          action="store_true")
    sub.add_parser("apply")
    sub.add_parser("inspect")
    p_config = sub.add_parser("config")
    p_config.add_argument("--declared", action="store_true", dest="config_declared")
    p_logs = sub.add_parser("logs")
    # --audit filters the stream to the structured `[audit]` events (#24):
    # credential-use and rule-hit records, pretty-printed (or raw JSON with
    # --json). Without it, `logs` streams the full proxy log verbatim.
    p_logs.add_argument("--audit", action="store_true", dest="logs_audit")

    p_bind = sub.add_parser("bind-dir")
    # Defaults to the current directory; --dir associates a different one.
    p_bind.add_argument("--dir", dest="bind_directory", default=None, metavar="PATH")

    binding = sub.add_parser("binding")
    bsub = binding.add_subparsers(dest="bindingcmd", required=True)
    _binding_subparsers(bsub)

    mount = sub.add_parser("mount")
    msub = mount.add_subparsers(dest="mountcmd", required=True)
    _mount_subparsers(msub)

    rule = sub.add_parser("rule")
    rsub = rule.add_subparsers(dest="rulecmd", required=True)
    _rule_subparsers(rsub)

    return parser


# ---- top-level dispatch ------------------------------------------------------


def _print_help(loose: bool = False) -> None:
    say(_LOOSE_HELP if loose else _STRICT_HELP)


_STRICT_HELP = (
    "credproxy -- workspace manager for the credential-injecting proxy.\n"
    "\n"
    "Strict surface: name every workspace explicitly, no default resolution,\n"
    "no prompts. The scriptable contract. `credp` is the human alias\n"
    "(`credproxy --loose`): default-workspace resolution, short aliases, and a\n"
    "confirmation gate on destructive actions -- run `credp --help` for that.\n"
    "\n"
    "Workspaces:\n"
    "  credproxy workspace create NAME\n"
    "  credproxy workspace list [FILTER]   (or: credproxy list [FILTER])\n"
    "  credproxy info                      (global config & state: paths, profile, registries)\n"
    "  credproxy workspace NAME enter|edit|start|stop|recreate|delete|apply|inspect|logs\n"
    "  credproxy workspace NAME bind-dir [--dir PATH]   (associate with a directory)\n"
    "  credproxy workspace NAME mount add --volume NAME --target PATH [--ro] [--preserve] [--user-owned]\n"
    "  credproxy workspace NAME binding add|remove|list|test ...\n"
    "  credproxy workspace binding test --provider P --secret REF [--injector I]\n"
    "      (ad-hoc: test a definition before binding it; no workspace needed)\n"
    "Definitions:\n"
    "  credproxy injector scaffold NAME [--script] | list | check NAME | api\n"
    "  credproxy provider scaffold NAME | provider list | show NAME\n"
    "  credproxy preset list               (coordinated multi-binding sets)\n"
    "Dev harness:\n"
    "  credproxy dev build|test|reload\n"
    "\n"
    "Global flags: --loose (human surface; use the `credp` alias), --json,\n"
    "  --yes (bypass confirmation)."
)


_LOOSE_HELP = (
    "credp -- human surface for credproxy (credproxy --loose).\n"
    "\n"
    "An omitted workspace resolves to the current default (announced on\n"
    "stderr); destructive actions on the default workspace ask first.\n"
    "\n"
    "Workspaces (omit NAME to resolve by current directory, then the default):\n"
    "  credp use NAME                  set the default workspace\n"
    "  credp current                   show the workspace a bare command targets\n"
    "  credp create [NAME] [--here]    (NAME derived from the dir if omitted)\n"
    "  credp bind-dir [NAME] [--dir PATH]  associate a workspace with a directory\n"
    "  credp list [FILTER]\n"
    "  credp info                      global config & state (paths, profile, registries)\n"
    "  credp enter|edit|start|stop|recreate|delete|apply|inspect|logs [NAME]\n"
    "  credp mount add --volume NAME --target PATH [--ro] [--preserve] [--user-owned]\n"
    "  credp binding add|remove|list|test ...   (acts on the default workspace)\n"
    "  credp binding test --provider P --secret REF [--injector I]\n"
    "      (ad-hoc: test a definition before binding it; no workspace needed)\n"
    "Definitions:\n"
    "  credp injector scaffold NAME [--script] | list | check NAME | api\n"
    "  credp provider scaffold NAME | provider list | show NAME\n"
    "  credp preset list               (coordinated multi-binding sets)\n"
    "Dev harness:\n"
    "  credp dev build|test|reload\n"
    "\n"
    "The canonical `credproxy workspace NAME <verb>` forms work too and are the\n"
    "scriptable contract. Global flags: --json, --yes (bypass confirmation)."
)


# Per-command help. The leaf parsers are deliberately `add_help=False` (we don't
# want raw argparse usage spew), so `--help` is honored by the hand-rolled
# dispatch via these prose blocks instead.
_BINDING_ADD_HELP = (
    "credproxy workspace NAME binding add -- bind a credential into requests\n"
    "for one or more hosts. Give exactly ONE of --injector or --preset.\n"
    "\n"
    "  --injector INJ    single binding: how the credential is shaped into the\n"
    "                    request (bearer, basic, body, sigv4, ...).\n"
    "                    See `credproxy injector list`.\n"
    "  --preset PRESET   a coordinated multi-binding set (e.g. github expands to\n"
    "                    three bindings sharing one token). The preset owns\n"
    "                    name/placeholder/env/host. See `credproxy preset list`.\n"
    "                    `github` defaults provider->gh-cli, secret->github.com,\n"
    "                    so `binding add --preset github` needs no other flags.\n"
    "  --provider PROV   where the value comes from. Required, except a preset\n"
    "                    may supply a default. See `credproxy provider list`.\n"
    "  --secret REF      the reference the provider resolves. For the `env`\n"
    "                    provider REF is the host env var NAME (not the value).\n"
    "                    Repeat as SLOT=REF for a multi-slot secret. May be\n"
    "                    defaulted by a preset (only for its default provider).\n"
    "  --host HOST       host this binding applies to; repeatable. Required\n"
    "                    with --injector (the preset sets its own hosts).\n"
    "  --name NAME       binding name (auto: <injector>-<provider>[-N]).\n"
    "  --placeholder PH  inert sentinel swapped for the real value at egress\n"
    "                    (auto-generated for substitute schemes).\n"
    "  --env VAR         env var name exposed to the workspace via /setup.\n"
)

_BINDING_TEST_HELP = (
    "credproxy workspace NAME binding test [BINDING] -- dry-run resolve binding\n"
    "secrets via their providers. Reports ok/length per binding (never the\n"
    "secret value); exits 1 if any fail.\n"
    "\n"
    "  BINDING                       test only this binding (default: all).\n"
    "  --provider P --secret REF [--injector I]\n"
    "                                ad-hoc: test a definition before it is\n"
    "                                bound (no workspace needed).\n"
)

_MOUNT_ADD_HELP = (
    "credproxy workspace NAME mount add -- add a managed-volume mount to the\n"
    "workspace (a named, persistent, per-workspace Docker volume).\n"
    "\n"
    "  --volume NAME   the volume's name (letters/digits/_.-). `home` writes the\n"
    "                  `home = ...` sugar instead of a mounts entry.\n"
    "  --target PATH   absolute path the volume mounts at inside the workspace.\n"
    "  --ro            mount read-only.\n"
    "  --preserve      seed the new volume with the CURRENT container's data at\n"
    "                  --target before applying. A mount can't attach to a live\n"
    "                  container, so this stops + recreates the workspace (which\n"
    "                  carries the data across); without it the volume starts\n"
    "                  empty/image-seeded and the change is deferred to `start`.\n"
    "                  On a running workspace with live `enter` sessions it asks\n"
    "                  first (loose) / needs --yes (strict), since they're killed.\n"
    "  --user-owned    chown the volume to the workspace `user` (after setup) so a\n"
    "                  non-root user can write it -- needed when it mounts at a path\n"
    "                  the image doesn't populate (else root-owned). Requires a\n"
    "                  non-root `user`; not valid for the `home` sugar.\n"
)

_RULE_ADD_HELP = (
    "credproxy workspace NAME rule add ACTION --host HOST [--host HOST...] ...\n"
    "  Govern traffic on an intercepted host (no credential involved). ACTION is a\n"
    "  SUBCOMMAND -- one of block|respond|rewrite|script (not a flag). Adding a rule\n"
    "  to a passthrough host makes it TLS-intercepted (workspace must bootstrap CA).\n"
    "\n"
    "  Scoping (every action):\n"
    "    --host HOST|GLOB   literal or glob (`*.amazonaws.com`); repeatable, required\n"
    "    --method METHOD    restrict to these methods (repeatable; default all)\n"
    "    --path GLOB        path glob: `*` within a segment, `**` across\n"
    "                       (e.g. /repos/**); default all paths\n"
    "    --name NAME        rule name (auto-generated if omitted)\n"
    "    --visible/--hidden override the per-family enumeration+attribution default\n"
    "                       (block/respond visible; rewrite/script hidden)\n"
    "\n"
    "  Per action (each owns exactly these flags):\n"
    "    block    [--status N]                              refuse (default 403)\n"
    "    respond  --status N [--body TEXT] [--header K=V...] stub a response\n"
    "    rewrite  [--header K=V] [--remove-header NAME]      request headers\n"
    "             [--resp-header K=V] [--resp-remove-header NAME]  response headers\n"
    "    script   --script NAME                             a .star rule script\n"
    "\n"
    "  Examples:\n"
    "    rule add block --host api.github.com --method DELETE --path '/repos/**'\n"
    "    rule add respond --host api.openai.com --path /v1/models --status 200 --body '{}'\n"
    "    rule add script --host api.github.com --path '/users/**' --script scrub-emails\n"
    "\n"
    "  A visible block self-identifies (X-Credproxy-Rule header + a credproxy JSON\n"
    "  body); a hidden block is a bare status. Hidden rules are excluded from\n"
    "  /setup but ALWAYS logged/audited for the operator. See docs/rules.md."
)

_CREATE_HELP = (
    "credproxy workspace create NAME -- scaffold a workspace config file and\n"
    "auth token (does not start anything). The scaffold sets a concrete image;\n"
    "edit the generated <name>.toml to change it (its comments show what to\n"
    "adjust), or override the template in a profile overlay (see docs/forking.md).\n"
    "\n"
    "  --here        associate the workspace with the current directory, so a\n"
    "                loose `credp <verb>` run from at/under it resolves here.\n"
    "  --dir PATH    associate with PATH instead of the current directory.\n"
    "\n"
    "On the loose surface (`credp`), NAME may be omitted with --here/--dir: it is\n"
    "derived from the directory's basename (sanitized to the name charset, and\n"
    "deduped with a numeric suffix). Strict `credproxy` always requires NAME.\n"
)


def _wants_help(argv: list[str]) -> bool:
    """True if argv contains a help flag. Used by the hand-rolled dispatch to
    honor `-h`/`--help` on subcommands (the leaf argparse parsers suppress it)."""
    return any(t in ("-h", "--help") for t in argv)


def _scaffold_help(kind: str) -> str:
    s = (
        f"credproxy {kind} scaffold NAME -- copy the builtin {kind} template "
        f"into\nyour registry as NAME, to author from. NAME must not start "
        f"with '-'."
    )
    if kind == "injector":
        s += (
            "\n\n--script [sign|substitute]  instead emit a SCRIPTED (custom) "
            "injector\n  (a manifest + a .star with the primitive-API reference "
            "inline) -- use\n  this when no built-in scheme fits. Pick the family:\n"
            "    sign        compute auth material on every request (e.g. an HMAC\n"
            "                signature); no placeholder. [default]\n"
            "    substitute  swap an inert placeholder the workspace holds for the\n"
            "                real secret value.\n"
            "  See `injector api` for the full reference; check it with "
            "`injector check NAME`."
        )
    if kind == "provider":
        s += (
            "\n\n--lang [python|sh]  template language (default python; "
            "sh = POSIX shell + jq).\n\n"
            "A provider is ANY executable -- a script in any language, or a "
            "compiled\nbinary -- that speaks the JSON stdin/stdout protocol "
            "(docs/providers.md);\nit can also be a directory with an executable "
            "`run`."
        )
    s += f"\nThen `credproxy {kind} list` shows it."
    return s


# What each workspace-scoped verb does, surfaced on `... NAME <verb> --help`.
# Kept terse but descriptive: the blind-agent rounds showed a bare `usage:`
# line for the lifecycle verbs read as "is this command even doing anything?".
_VERB_HELP = {
    "enter": (
        "credproxy workspace NAME enter [--user USER] [--push] [-- CMD...] -- open\n"
        "a shell (default bash, or run CMD) in the workspace, starting it if needed.\n"
        "  --user USER   run as USER for this session (overrides config `user`).\n"
        "  --push        force a config re-push (re-resolve secrets) even if the\n"
        "                proxy already has the current config -- e.g. after\n"
        "                rotating a secret in place. Default skips the redundant push."
    ),
    "start": (
        "credproxy workspace NAME start -- (re)start the proxy, wait for health,\n"
        "push the resolved bindings, then (re)start the workspace. Creates the\n"
        "containers if missing; recreates one whose spec (image/mounts/env/...)\n"
        "has drifted. Safe to re-run."
    ),
    "stop": (
        "credproxy workspace NAME stop -- stop both containers (kept, not removed).\n"
        "Config and state survive; a later `start`/`enter` resumes."
    ),
    "recreate": (
        "credproxy workspace NAME recreate [--proxy] [--reset-volume NAME ...] --\n"
        "rebuild the workspace container from a clean slate (re-runs setup), then\n"
        "start it. Keeps all managed volumes, config, auth token, and state -- only\n"
        "the container is replaced (unlike `delete`). `--proxy` (alias `--all`) also\n"
        "recreates the proxy container, regenerating its CA (full re-bootstrap).\n"
        "`--reset-volume NAME` (repeatable) ALSO wipes that managed volume,\n"
        "re-seeded from the image (e.g. `--reset-volume home`) -- bind/profile\n"
        "host-path mounts are untouched, and config/token/state survive. It\n"
        "destroys data, so on the loose surface it prompts for an implicit default\n"
        "workspace (pass --yes to bypass)."
    ),
    "delete": (
        "credproxy workspace NAME delete [--keep-volumes] -- remove both\n"
        "containers, the workspace's managed volumes, the config file, and the\n"
        "state dir. `--keep-volumes` preserves the volumes (they orphan unless a\n"
        "same-named workspace is recreated). Not reversible. (On the loose surface,\n"
        "deleting the default workspace prompts first.)"
    ),
    "apply": (
        "credproxy workspace NAME apply -- reconcile a running workspace with its\n"
        "config: binding changes are re-pushed live; container-spec changes\n"
        "(image/home/mounts/env/setup) are deferred with a `start` hint. Reports\n"
        "what was applied vs deferred."
    ),
    "inspect": (
        "credproxy workspace NAME inspect -- show config, running state, host port,\n"
        "binding summary, and any drift against what was last applied."
    ),
    "config": (
        "credproxy workspace NAME config [--declared] -- dump the container-side\n"
        "config. Default `effective`: every field with its in-effect value, all\n"
        "defaults filled (so you see what applies even when it's not in the file).\n"
        "`--declared` shows only what's literally in the .toml. `--json` for both."
    ),
    "edit": (
        "credproxy workspace NAME edit -- open the config in $VISUAL/$EDITOR\n"
        "(default vi), then validate it. Sugar over editing the .toml directly;\n"
        "hints `apply`/`start` afterward."
    ),
    "logs": (
        "credproxy workspace NAME logs -- follow the proxy container's logs\n"
        "(docker logs -f)."
    ),
    "bind-dir": (
        "credproxy workspace NAME bind-dir [--dir PATH] -- associate the workspace\n"
        "with a host directory (default: the current directory), so a loose\n"
        "`credp <verb>` run from at or under it resolves to NAME. Sugar over\n"
        "editing the `directory` field in the .toml (the source of truth)."
    ),
}


def _verb_help(verb_argv: list[str]) -> str:
    """Contextual help for a workspace-scoped verb (`--help` on the leaf)."""
    verb = verb_argv[0] if verb_argv else ""
    if verb == "binding":
        sub = verb_argv[1] if len(verb_argv) > 1 and not verb_argv[1].startswith("-") else ""
        if sub == "add":
            return _BINDING_ADD_HELP
        if sub == "test":
            return _BINDING_TEST_HELP
        return ("credproxy workspace NAME binding {add|remove|list|test} ...\n"
                "Run `binding add --help` or `binding test --help` for details.")
    if verb == "mount":
        sub = verb_argv[1] if len(verb_argv) > 1 and not verb_argv[1].startswith("-") else ""
        if sub == "add":
            return _MOUNT_ADD_HELP
        return ("credproxy workspace NAME mount add ...\n"
                "Run `mount add --help` for details.")
    if verb == "rule":
        sub = verb_argv[1] if len(verb_argv) > 1 and not verb_argv[1].startswith("-") else ""
        if sub == "add":
            return _RULE_ADD_HELP
        return ("credproxy workspace NAME rule {add|remove|list|test} ...\n"
                "Rules govern traffic on intercepted hosts (block/respond/rewrite/\n"
                "script), credential-free. `rule test METHOD URL` dry-runs the\n"
                "matcher. Run `rule add --help` for details.")
    if verb in _VERB_HELP:
        return _VERB_HELP[verb]
    return f"usage: credproxy workspace NAME {verb}"


def _split_trailing(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split off a `-- CMD...` tail (for `enter` and `dev test`)."""
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def _pop_global_flags(argv: list[str]) -> tuple[list[str], bool, bool, bool]:
    """Pull the order-independent global flags (--loose/--json/--yes) out of
    argv wherever they appear, returning the remainder and the flag values."""
    loose = as_json = assume_yes = False
    rest = []
    for tok in argv:
        if tok == "--loose":
            loose = True
        elif tok == "--json":
            as_json = True
        elif tok in ("--yes", "-y"):
            assume_yes = True
        else:
            rest.append(tok)
    return rest, loose, as_json, assume_yes


def _dispatch_workspace(ctx: Ctx, rest: list[str], trailing: list[str]) -> None:
    """Hand-rolled router for the `workspace` noun.

    `rest` is everything after `workspace`. Peek the first token:
      - a workspace-level verb (`create`/`use`/`list`) -> handle directly;
      - a workspace-scoped verb (`enter`/.../`binding`) with NO name -> in
        loose mode resolve the default; in strict mode this is an error;
      - otherwise the first token is a workspace NAME and the next is the
        scoped verb.
    """
    if not rest:
        fail("usage: credproxy workspace {create|use|list|NAME <verb>}")

    head = rest[0]

    if head == "create":
        if _wants_help(rest):
            say(_CREATE_HELP)
            return
        a = _parse_create(rest[1:])
        do_create(ctx, a.name, _create_dir(a))
        return
    if head == "use":
        # `use` mutates the loose default-workspace pointer, so it's loose-only
        # (strict names every workspace explicitly). Its reader, `current`, is
        # loose-only too -- both sides of the default concept live on loose.
        if not ctx.loose:
            fail("`workspace use` sets the loose default-workspace pointer; it is "
                 "loose-only -- use the `credp` alias (or `credproxy --loose`). "
                 "The strict surface names every workspace explicitly.")
        if len(rest) != 2:
            fail("usage: credp workspace use NAME")
        do_use(ctx, rest[1])
        return
    if head == "list":
        if len(rest) > 2:
            fail("usage: credproxy workspace list [FILTER]")
        do_list(ctx, rest[1] if len(rest) > 1 else None)
        return

    if head in _WS_VERBS:
        # Verb with no explicit name -> default resolution (loose) / error.
        _run_ws_verb(ctx, None, rest, trailing)
        return

    # Otherwise head is a workspace name; rest[1:] is `<verb> ...`.
    name = head
    if len(rest) < 2:
        fail(f"usage: credproxy workspace {name} <verb>")
    _run_ws_verb(ctx, name, rest[1:], trailing)


def _run_ws_verb(
    ctx: Ctx, name: str | None, verb_argv: list[str], trailing: list[str]
) -> None:
    """Parse and run a workspace-scoped verb. `verb_argv` starts with the
    verb. `name` is the (possibly None) explicit workspace name."""
    if _wants_help(verb_argv):
        say(_verb_help(verb_argv))
        return
    a = _build_leaf_parser().parse_args(verb_argv)
    verb = a.verb
    if verb == "enter":
        do_enter(ctx, name, trailing, a.enter_user, a.enter_push)
    elif verb == "edit":
        do_edit(ctx, name)
    elif verb == "start":
        do_start(ctx, name)
    elif verb == "stop":
        do_stop(ctx, name)
    elif verb == "delete":
        do_delete(ctx, name, a.delete_keep_volumes)
    elif verb == "apply":
        do_apply(ctx, name)
    elif verb == "recreate":
        do_recreate(ctx, name, a.recreate_proxy, a.recreate_reset_volumes)
    elif verb == "inspect":
        do_inspect(ctx, name)
    elif verb == "config":
        do_config(ctx, name, a.config_declared)
    elif verb == "logs":
        do_logs(ctx, name, getattr(a, "logs_audit", False))
    elif verb == "bind-dir":
        do_bind_dir(ctx, name, a.bind_directory)
    elif verb == "binding":
        bc = a.bindingcmd
        if bc == "add":
            do_binding_add(ctx, name, a)
        elif bc == "remove":
            do_binding_remove(ctx, name, a)
        elif bc == "list":
            do_binding_list(ctx, name)
        elif bc == "test":
            do_binding_test(ctx, name, a)
    elif verb == "mount":
        if a.mountcmd == "add":
            do_mount_add(ctx, name, a)
    elif verb == "rule":
        rc = a.rulecmd
        if rc == "add":
            do_rule_add(ctx, name, a)
        elif rc == "remove":
            do_rule_remove(ctx, name, a)
        elif rc == "list":
            do_rule_list(ctx, name)
        elif rc == "test":
            do_rule_test(ctx, name, a)


def _parse_create(argv: list[str]) -> argparse.Namespace:
    p = _LeafParser(prog="credproxy workspace create", add_help=False)
    # Optional: on the loose surface, an omitted NAME is derived from the
    # --here/--dir directory basename (strict still requires it). See do_create.
    p.add_argument("name", nargs="?", default=None)
    # Associate the new workspace with a host directory, so `credp <verb>` run
    # from at/under it resolves here. --here uses the current directory.
    p.add_argument("--here", action="store_true")
    p.add_argument("--dir", dest="directory", default=None, metavar="PATH")
    return p.parse_args(argv)


def _create_dir(a: argparse.Namespace) -> str | None:
    """Resolve the directory association from `create` flags (--here/--dir)."""
    if a.here and a.directory is not None:
        fail("give --here or --dir, not both")
    if a.here:
        return os.getcwd()
    if a.directory is not None:
        return os.path.abspath(os.path.expanduser(a.directory))
    return None


# ---- loose aliases -----------------------------------------------------------
#
# In loose mode, short top-level verbs resolve to canonical commands with NO
# independent behavior. They simply translate to the workspace dispatcher.

_ALIAS_TO_WS_VERB = {
    "enter", "edit", "start", "stop", "recreate", "delete", "apply", "inspect",
    "config", "logs", "binding", "bind-dir", "mount", "rule",
}


def _dispatch_alias(ctx: Ctx, head: str, rest: list[str], trailing: list[str]) -> None:
    """Loose-only top-level aliases. `head` is the alias verb already consumed;
    `rest` is what follows."""
    if head == "use":
        if len(rest) != 1:
            fail("usage: credp use NAME")
        do_use(ctx, rest[0])
        return
    if head == "create":
        if _wants_help(rest):
            say(_CREATE_HELP)
            return
        a = _parse_create(rest)
        do_create(ctx, a.name, _create_dir(a))
        return
    if head == "list":
        do_list(ctx, rest[0] if rest else None)
        return

    if head == "binding":
        # `credp binding <subcmd> ... [NAME]` -> resolve default workspace.
        # NAME is never given on the alias (the alias assumes the default);
        # an explicit workspace uses the canonical `workspace NAME binding`.
        _run_ws_verb(ctx, None, ["binding", *rest], trailing)
        return

    if head == "mount":
        # Like `binding`: the sub-noun's subcommand (`add`) would otherwise be
        # eaten as a NAME by the generic alias path below. The alias always acts
        # on the resolved default workspace; explicit names use the canonical
        # `workspace NAME mount` form.
        _run_ws_verb(ctx, None, ["mount", *rest], trailing)
        return

    if head == "rule":
        # Same as `binding`/`mount`: the sub-noun's subcommand would be eaten as
        # a NAME by the generic path. Always acts on the resolved default
        # workspace; explicit names use `workspace NAME rule`.
        _run_ws_verb(ctx, None, ["rule", *rest], trailing)
        return

    if head in _ALIAS_TO_WS_VERB:
        # A leading non-flag token overrides the default workspace
        # (`credp enter myproj`); flags are forwarded to the verb parser
        # (`credp enter --user root`, optionally `credp enter myproj --user root`).
        name = None
        verb_args = list(rest)
        if verb_args and not verb_args[0].startswith("-"):
            name = verb_args.pop(0)
        _run_ws_verb(ctx, name, [head, *verb_args], trailing)
        return

    fail(f"unknown command '{head}'")


# ---- main --------------------------------------------------------------------


def main_loose() -> None:
    """Console-script entry point for the loose surface (`credp`), equivalent to
    `credproxy --loose`. The strict surface uses `main` directly. (The `bin/`
    shims call `main(loose_default=...)` and stay the no-install path.)"""
    main(loose_default=True)


def main(loose_default: bool = False) -> None:
    argv = sys.argv[1:]

    argv, trailing = _split_trailing(argv)
    argv, loose, as_json, assume_yes = _pop_global_flags(argv)
    loose = loose or loose_default

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_help(loose)
        sys.exit(0)

    render.set_format(as_json)
    ctx = Ctx(loose=loose, as_json=as_json, assume_yes=assume_yes)

    head, rest = argv[0], argv[1:]

    try:
        if head == "workspace":
            _dispatch_workspace(ctx, rest, trailing)
        elif head in _META_COMMANDS:
            _dispatch_meta(ctx, head, rest)
        elif head in ("injector", "provider"):
            _dispatch_def(ctx, head, rest)
        elif head == "preset":
            _dispatch_preset(ctx, rest)
        elif head == "dev":
            _dispatch_dev(ctx, rest, trailing)
        elif loose:
            # Loose surface: top-level aliases.
            _dispatch_alias(ctx, head, rest, trailing)
        else:
            fail(
                f"unknown command '{head}' "
                f"(strict surface; see `credproxy --help`)"
            )
    except CredproxyError as e:
        fail(e)


def _dispatch_meta(ctx: Ctx, head: str, rest: list[str]) -> None:
    """Top-level meta commands (no workspace argument)."""
    if head == "list":
        if len(rest) > 1:
            fail("usage: credproxy list [FILTER]")
        do_list(ctx, rest[0] if rest else None)
    elif head == "current":
        # `current` reports the loose default/cwd-resolved target -- an implicit-
        # targeting concept the strict surface disclaims (like its writer, `use`).
        if not ctx.loose:
            fail("`current` reports the loose default/cwd-resolved workspace; it "
                 "is loose-only -- use the `credp` alias (or `credproxy --loose`). "
                 "The strict surface names every workspace explicitly.")
        if rest:
            fail("usage: credp current (takes no arguments)")
        do_current(ctx)
    elif head == "info":
        if rest:
            fail("usage: credproxy info (takes no arguments)")
        do_info(ctx)


def _dispatch_def(ctx: Ctx, kind: str, rest: list[str]) -> None:
    sub = rest[0] if rest else None

    if sub == "scaffold":
        args = rest[1:]
        # Honor --help BEFORE treating the next token as a NAME -- otherwise
        # `scaffold --help` would scaffold a file literally named '--help'.
        if _wants_help(args):
            say(_scaffold_help(kind))
            return
        name, script_mode, family, lang = _parse_scaffold_args(kind, args)
        if script_mode:
            if kind != "injector":
                fail("--script is only valid for `injector scaffold`")
            do_scaffold_script(ctx, name, family)
        else:
            do_scaffold(ctx, kind, name, lang)
        return

    if sub == "check" and kind == "injector":
        args = rest[1:]
        if _wants_help(args) or not args:
            say("usage: credproxy injector check NAME [--compile]\n"
                "Validate a scripted injector host-side (manifest parses and the\n"
                "named .star resolves); --compile additionally compiles the .star\n"
                "in the proxy image (needs docker + the built image).")
            return
        names = [a for a in args if not a.startswith("-")]
        flags = [a for a in args if a.startswith("-")]
        bad = [f for f in flags if f != "--compile"]
        if bad or len(names) != 1:
            fail("usage: credproxy injector check NAME [--compile]")
        do_injector_check(ctx, names[0], "--compile" in flags)
        return

    if sub == "api" and kind == "injector":
        if _wants_help(rest[1:]):
            say("usage: credproxy injector api\n"
                "Print the scripted-injector authoring reference (manifest fields\n"
                "+ the Starlark primitive API) without scaffolding anything.")
            return
        do_injector_api(ctx)
        return

    if sub == "show" and kind == "provider":
        args = rest[1:]
        names = [a for a in args if not a.startswith("-")]
        if _wants_help(args) or len(names) != 1:
            say("usage: credproxy provider show NAME\n"
                "Show a provider's source, resolved path, description, and help.")
            return
        do_provider_show(ctx, names[0])
        return

    if sub == "list":
        do_def_list(ctx, kind)
        return

    usage = (
        "usage: credproxy injector {scaffold NAME [--script [sign|substitute]]"
        "|list|check NAME|api}"
        if kind == "injector"
        else "usage: credproxy provider {scaffold NAME|list|show NAME}"
    )
    if _wants_help(rest):
        say(usage)
        return
    if not rest:
        fail(usage)
    fail(f"unknown {kind} command '{rest[0]}'")


def _parse_scaffold_args(kind: str, args: list[str]) -> tuple[str, bool, str, str]:
    """Parse `scaffold` args: a NAME plus optional `--script [sign|substitute]`
    (injector) or `--lang python|sh` (provider)."""
    name: str | None = None
    script_mode = False
    family = "sign"
    lang = "python"
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--script":
            script_mode = True
            if i + 1 < len(args) and args[i + 1] in ("sign", "substitute"):
                family = args[i + 1]
                i += 1
        elif tok == "--lang":
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                fail("--lang needs a value (python or sh)")
            lang = args[i + 1]
            i += 1
        elif tok.startswith("-"):
            fail(f"unknown flag {tok!r}; usage: credproxy {kind} scaffold NAME "
                 f"[--script [sign|substitute]] [--lang python|sh]")
        elif name is None:
            name = tok
        else:
            fail(f"usage: credproxy {kind} scaffold NAME")
        i += 1
    if name is None:
        fail(f"usage: credproxy {kind} scaffold NAME")
    return name, script_mode, family, lang


def do_scaffold_script(ctx: Ctx, name: str, family: str) -> None:
    from ..core.scaffold import scaffold_script

    r = scaffold_script(name, family)
    render.OUT.scaffolded_script(
        r.name, str(r.injector_path), str(r.script_path), r.family)


def do_injector_api(ctx: Ctx) -> None:
    from ..core.scaffold import script_api_reference

    render.OUT.injector_api(script_api_reference())


def do_injector_check(ctx: Ctx, name: str, do_compile: bool) -> None:
    from ..core.injectors import find_injector
    from ..core.scripts import find_script

    inj = find_injector(name)  # parses + validates the manifest (raises if bad)
    if inj.scheme != "script":
        render.OUT.injector_check(name, {
            "scheme": inj.scheme, "scripted": False, "ok": True,
            "detail": f"built-in scheme '{inj.scheme}'; nothing to compile"})
        return
    script = find_script(inj.script)  # raises InjectorError if missing
    detail = (f"manifest ok (family={inj.spec.family}, "
              f"slots={list(inj.spec.slots)}); script '{inj.script}' "
              f"resolves ({script.source_origin})")
    if not do_compile:
        render.OUT.injector_check(name, {
            "scheme": "script", "scripted": True, "ok": True,
            "compiled": False, "detail": detail})
        return
    err = _compile_script_in_image(script.source)
    render.OUT.injector_check(name, {
        "scheme": "script", "scripted": True, "ok": err is None,
        "compiled": True, "detail": detail, "compile_error": err})
    if err is not None:
        sys.exit(1)


def _compile_script_in_image(source: str) -> str | None:
    """Compile a `.star` in the proxy image (which carries the Starlark runtime),
    so the host needs no starlark dep. Returns None on success, else the error
    text. Mirrors what the proxy does at push time. Needs docker + the image."""
    import os
    import subprocess
    import tempfile

    pycode = (
        "import sys\n"
        "from starlark_runtime import ScriptedScheme\n"
        "src = open('/work/check.star').read()\n"
        "try:\n"
        "    ScriptedScheme(name='check', source=src, filename='check.star')\n"
        "except Exception as e:\n"
        "    print('%s: %s' % (type(e).__name__, e)); sys.exit(1)\n"
        "print('ok')\n"
    )
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o755)
        p = os.path.join(d, "check.star")
        with open(p, "w") as f:
            f.write(source)
        os.chmod(p, 0o644)
        cmd = ["docker", "run", "--rm", "-v", f"{d}:/work:ro"]
        # Prefer the live proxy source when the repo is checked out (parity with
        # `dev test`), so a `dev build`-stale image doesn't give wrong verdicts;
        # otherwise the baked image's runtime is the contract.
        if PROXY_DIR.is_dir():
            cmd += ["-v", f"{PROXY_DIR}:/opt/proxy:ro"]
        cmd += ["-w", "/opt/proxy", "--entrypoint", "python", IMAGE_TAG,
                "-c", pycode]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            fail("`injector check --compile` needs docker (not found on PATH)")
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        return None
    if "Unable to find image" in out or "No such image" in out:
        fail(f"proxy image '{IMAGE_TAG}' not found; build it with "
             f"`credproxy dev build`")
    return out or f"compile failed (exit {r.returncode})"


def _dispatch_preset(ctx: Ctx, rest: list[str]) -> None:
    # One subcommand (`list`); a bare `preset` or `--help` also lists, since the
    # listing is the documentation. Anything else is a usage error.
    if not rest or _wants_help(rest) or rest[0] == "list":
        do_preset_list(ctx)
        return
    fail(f"unknown preset command '{rest[0]}' (usage: credproxy preset list)")


def _dispatch_dev(ctx: Ctx, rest: list[str], trailing: list[str]) -> None:
    usage = "usage: credproxy dev {build|test|reload}"
    if _wants_help(rest):
        say(usage)
        return
    if not rest:
        fail(usage)
    sub = rest[0]
    if sub == "build":
        do_dev_build(ctx)
    elif sub == "test":
        test_args = rest[1:]  # selection flags (pytest args go after `--`)
        _known = ("--cli", "--proxy", "--container", "--docker")
        unknown = [a for a in test_args if a not in _known]
        if unknown:
            fail(f"dev test: unknown flag(s) {' '.join(unknown)} "
                 f"(use --cli/--proxy/--container; pytest args go after `--`)")
        cli_only = "--cli" in test_args
        proxy_only = "--proxy" in test_args
        force_container = "--container" in test_args or "--docker" in test_args
        if cli_only and proxy_only:
            # Both = "neither" under the old logic, yet the proxy path still ran.
            fail("dev test: --cli and --proxy are mutually exclusive "
                 "(omit both to run both suites)")
        do_dev_test(ctx, trailing, cli_only=cli_only, proxy_only=proxy_only,
                    force_container=force_container)
    elif sub == "reload":
        do_dev_reload(ctx, rest[1] if len(rest) > 1 else None)
    else:
        fail(f"unknown dev command '{sub}'")
