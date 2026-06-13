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
    credproxy workspace create NAME [--image IMG]
    credproxy workspace use NAME
    credproxy workspace list [FILTER]
    credproxy list [FILTER]                       # canonical survey
    credproxy workspace NAME {enter|start|stop|delete|apply|inspect|logs}
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

from ..core import docker as core_docker
from ..core import lifecycle
from ..core import pointer
from ..core import workspace as core_workspace
from ..core.errors import CredproxyError
from ..core.workspace import RESERVED_NAMES, Workspace, for_name
from ..core.paths import (
    DEFAULT_WORKSPACE_IMAGE,
    PROXY_DIR,
    TESTS_DIR,
)
from . import render
from .render import fail, say


# Workspace-scoped verbs (the `workspace NAME <verb>` tail).
_WS_VERBS = {
    "enter", "start", "stop", "delete", "apply", "inspect", "logs", "binding",
}
# Workspace-level verbs that take a name as their argument, not a subject.
_WS_NOUN_VERBS = {"create", "use", "list"}


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
    LOOSE: a missing name falls back to the default pointer, and the
    resolution is announced on stderr."""
    if name is not None:
        return for_name(name)
    if not ctx.loose:
        fail("workspace name required (strict mode names every workspace)")
    ws = pointer.resolve_default()
    say(f"workspace: {ws.name} (default)")
    return ws


def _is_default(ws: Workspace) -> bool:
    return pointer.read_default() == ws.name


def _confirm_destructive(ctx: Ctx, ws: Workspace, implicit: bool, verb: str) -> None:
    """The safety gate. Fires only when a destructive command targets an
    IMPLICIT (defaulted) workspace, in LOOSE mode. Explicit targets never
    prompt. `--yes` bypasses. Fails closed without a TTY."""
    if not (ctx.loose and implicit):
        return
    if ctx.assume_yes:
        return
    if not sys.stdin.isatty():
        fail(
            f"refusing to {verb} the default workspace '{ws.name}' "
            f"without confirmation: stdin is not a TTY (pass --yes)"
        )
    suffix = "(current default)"
    reply = input(f'{verb.capitalize()} workspace "{ws.name}" {suffix}? [y/N] ')
    if reply.strip().lower() not in ("y", "yes"):
        fail("aborted")


def _require_exists(ws: Workspace) -> None:
    if not ws.exists():
        fail(f"workspace '{ws.name}' not found")


# ---- workspace commands ------------------------------------------------------


def do_create(ctx: Ctx, name: str, image: str) -> None:
    ws = for_name(name)  # always explicit; reserved-name check happens here
    lifecycle.create_workspace_files(ws, image)
    render.OUT.created(ws.name, str(ws.config_path))


def do_use(ctx: Ctx, name: str) -> None:
    ws = for_name(name)
    pointer.set_default(ws)  # verifies existence
    render.OUT.used(ws.name)


def do_current(ctx: Ctx) -> None:
    render.OUT.current(pointer.read_default())


def do_list(ctx: Ctx, filter_: str | None) -> None:
    default = pointer.read_default()
    rows = []
    for s in core_workspace.list_workspaces():
        if filter_ and filter_ not in s.name:
            continue
        rows.append({
            "name": s.name,
            "running": s.running,
            "image": s.image,
            "default": s.name == default,
        })
    render.OUT.workspace_list(rows)


def do_enter(ctx: Ctx, name: str | None, trailing: list[str]) -> None:
    if ctx.json:
        fail("enter does not support --json (it execs an interactive shell)")
    ws = _resolve_ws(ctx, name)
    cmd = trailing or ["bash"]
    exit_code = lifecycle.enter_workspace(ws, cmd, notify=say)
    sys.exit(exit_code)


def do_start(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    lifecycle.start_workspace(ws, notify=say)
    render.OUT.started(ws.name)


def do_stop(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    lifecycle.stop_workspace(ws)
    render.OUT.stopped(ws.name)


def do_delete(ctx: Ctx, name: str | None) -> None:
    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "delete")
    was_default = _is_default(ws)
    lifecycle.delete_workspace(ws)
    if was_default:
        pointer.clear_default()
    render.OUT.deleted(ws.name)


def do_apply(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    result = lifecycle.apply_config(ws, notify=say)
    render.OUT.applied(ws.name, result)


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


def do_logs(ctx: Ctx, name: str | None) -> None:
    ws = _resolve_ws(ctx, name)
    if ctx.json:
        _logs_json(ws)
        return
    os.execvp("docker", ["docker", "logs", "-f", ws.proxy_container])


def _logs_json(ws: Workspace) -> None:
    """JSON-lines log streaming: one `{"line": ...}` object per log line.
    The proxy's lines aren't structured yet, so we just wrap them."""
    import json
    import subprocess

    proc = subprocess.Popen(
        ["docker", "logs", "-f", ws.proxy_container],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(json.dumps({"line": line.rstrip("\n")}), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()


# ---- binding commands --------------------------------------------------------


def do_binding_add(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core import bindings as core_bindings
    from ..core.bindings import Binding
    from ..core.injectors import find_injector
    from ..core.providers import find_provider

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)

    injector = find_injector(a.injector)
    find_provider(a.provider)

    existing = core_bindings.load_bindings(ws)
    taken = {b.name for b in existing}
    bname = a.binding_name or core_bindings._auto_name(a.injector, a.provider, taken)
    if bname in taken:
        fail(f"binding name '{bname}' already exists in workspace '{ws.name}'")

    placeholder = a.placeholder or injector.placeholder.generate()
    env = a.env or injector.env

    binding = Binding(
        name=bname,
        injector=a.injector,
        provider=a.provider,
        secret=a.secret,
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


def do_binding_remove(ctx: Ctx, name: str | None, a: argparse.Namespace) -> None:
    from ..core import bindings as core_bindings

    implicit = name is None
    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
    _confirm_destructive(ctx, ws, implicit, "remove binding from")
    core_bindings.remove_binding(ws, a.binding_name)
    render.OUT.binding_removed(a.binding_name, ws.name)


def do_binding_list(ctx: Ctx, name: str | None) -> None:
    from ..core import bindings as core_bindings

    ws = _resolve_ws(ctx, name)
    _require_exists(ws)
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
    bindings = core_bindings.materialize_bindings(ws, notify=say)
    if a.binding_name is not None:
        bindings = [b for b in bindings if b.name == a.binding_name]
        if not bindings:
            fail(f"binding '{a.binding_name}' not found in workspace '{ws.name}'")

    results = []
    any_fail = False
    for b in bindings:
        r = core_bindings.test_binding(b)
        if not r.ok:
            any_fail = True
        results.append({
            "name": b.name,
            "provider": b.provider,
            "ok": r.ok,
            "value_len": r.value_len,
            "error": r.error,
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

    if not a.provider or not a.secret:
        fail("ad-hoc `binding test` needs --provider and --secret")
    if a.binding_name is not None:
        fail("cannot combine a binding NAME with ad-hoc --provider/--secret")

    find_provider(a.provider)  # raises ProviderError if it doesn't resolve
    label = a.provider
    if a.injector is not None:
        find_injector(a.injector)  # raises InjectorError if it doesn't resolve
        label = f"{a.injector}-{a.provider}"

    probe = core_bindings.Binding(
        name=label, injector=a.injector or "", provider=a.provider,
        secret=a.secret, hosts=(), placeholder=None, env=None,
    )
    r = core_bindings.test_binding(probe)
    render.OUT.binding_test([{
        "name": label,
        "provider": a.provider,
        "ok": r.ok,
        "value_len": r.value_len,
        "error": r.error,
    }])
    if not r.ok:
        sys.exit(1)


# ---- injector / provider -----------------------------------------------------


def do_scaffold(ctx: Ctx, kind: str, name: str) -> None:
    from ..core.scaffold import scaffold

    result = scaffold(kind, name)
    render.OUT.scaffolded(result.kind, result.name, str(result.path))


def do_def_list(ctx: Ctx, kind: str) -> None:
    if kind == "injector":
        from ..core.injectors import list_injectors
        rows = [{"name": d.name, "source": d.source} for d in list_injectors()]
    else:
        from ..core.providers import list_providers
        rows = [{"name": d.name, "source": d.source} for d in list_providers()]
    render.OUT.def_list(kind, rows)


# ---- dev harness -------------------------------------------------------------


def do_dev_build(ctx: Ctx) -> None:
    if not PROXY_DIR.is_dir():
        fail(f"{PROXY_DIR} not found -- `dev` commands need the repo checkout")
    from ..core.paths import IMAGE_TAG

    core_docker.docker(["build", "-t", IMAGE_TAG, str(PROXY_DIR)], stream=True)


def do_dev_test(ctx: Ctx, trailing: list[str], cli_only: bool = False, proxy_only: bool = False) -> None:
    """Run the test suite(s).

    Default: run BOTH the host-side CLI tests (tests/cli/, via the host's
    python3 -m pytest) and the proxy suite inside the image (tests/, via
    docker run). Trailing args after `--` pass through to the proxy pytest.

    --cli:   host CLI tests only (no docker required).
    --proxy: proxy in-container tests only.
    """
    import importlib.util
    import subprocess
    from ..core.imageenv import ImageEnv
    from ..core.paths import IMAGE_TAG, TESTS_DIR, REPO_ROOT

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

    # Proxy suite, in-container. tests/cli/ is host-only: it is excluded here
    # both because it needs no docker and because its module names (e.g.
    # test_config) collide with the proxy suite's under pytest's rootdir.
    meta = ImageEnv.load()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{PROXY_DIR}:{meta.source}",
        "-v", f"{TESTS_DIR}:/opt/tests",
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
    p.add_argument("--injector", required=True)
    p.add_argument("--provider", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--host", required=True, action="append", metavar="HOST")
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
    p.add_argument("--secret", default=None)


def _build_leaf_parser() -> argparse.ArgumentParser:
    """Parser for the verb tail of a workspace-scoped command. The dispatcher
    has already stripped `workspace` and the workspace name; what remains is
    `<verb> [args]`. NAME is threaded separately (resolved by the dispatcher)."""
    parser = argparse.ArgumentParser(prog="credproxy workspace", add_help=False)
    sub = parser.add_subparsers(dest="verb", required=True)

    sub.add_parser("enter")
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("delete")
    sub.add_parser("apply")
    sub.add_parser("inspect")
    sub.add_parser("logs")

    binding = sub.add_parser("binding")
    bsub = binding.add_subparsers(dest="bindingcmd", required=True)
    _binding_subparsers(bsub)

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
    "  credproxy workspace create NAME [--image IMG]\n"
    "  credproxy workspace use NAME\n"
    "  credproxy workspace list [FILTER]   (or: credproxy list [FILTER])\n"
    "  credproxy current                   (print the default workspace)\n"
    "  credproxy workspace NAME enter|start|stop|delete|apply|inspect|logs\n"
    "  credproxy workspace NAME binding add|remove|list|test ...\n"
    "  credproxy workspace binding test --provider P --secret REF [--injector I]\n"
    "      (ad-hoc: test a definition before binding it; no workspace needed)\n"
    "Definitions:\n"
    "  credproxy injector scaffold NAME | injector list\n"
    "  credproxy provider scaffold NAME | provider list\n"
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
    "Workspaces (omit NAME to act on the default):\n"
    "  credp use NAME                  set the default workspace\n"
    "  credp current                   print the default workspace\n"
    "  credp create NAME [--image IMG]\n"
    "  credp list [FILTER]\n"
    "  credp enter|start|stop|delete|apply|inspect|logs [NAME]\n"
    "  credp binding add|remove|list|test ...   (acts on the default workspace)\n"
    "  credp binding test --provider P --secret REF [--injector I]\n"
    "      (ad-hoc: test a definition before binding it; no workspace needed)\n"
    "Definitions:\n"
    "  credp injector scaffold NAME | injector list\n"
    "  credp provider scaffold NAME | provider list\n"
    "Dev harness:\n"
    "  credp dev build|test|reload\n"
    "\n"
    "The canonical `credproxy workspace NAME <verb>` forms work too and are the\n"
    "scriptable contract. Global flags: --json, --yes (bypass confirmation)."
)


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
        a = _parse_create(rest[1:])
        do_create(ctx, a.name, a.image)
        return
    if head == "use":
        if len(rest) != 2:
            fail("usage: credproxy workspace use NAME")
        do_use(ctx, rest[1])
        return
    if head == "list":
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
    a = _build_leaf_parser().parse_args(verb_argv)
    verb = a.verb
    if verb == "enter":
        do_enter(ctx, name, trailing)
    elif verb == "start":
        do_start(ctx, name)
    elif verb == "stop":
        do_stop(ctx, name)
    elif verb == "delete":
        do_delete(ctx, name)
    elif verb == "apply":
        do_apply(ctx, name)
    elif verb == "inspect":
        do_inspect(ctx, name)
    elif verb == "logs":
        do_logs(ctx, name)
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


def _parse_create(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="credproxy workspace create", add_help=False)
    p.add_argument("name")
    p.add_argument("--image", default=DEFAULT_WORKSPACE_IMAGE)
    return p.parse_args(argv)


# ---- loose aliases -----------------------------------------------------------
#
# In loose mode, short top-level verbs resolve to canonical commands with NO
# independent behavior. They simply translate to the workspace dispatcher.

_ALIAS_TO_WS_VERB = {
    "enter", "start", "stop", "delete", "apply", "inspect", "logs", "binding",
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
        a = _parse_create(rest)
        do_create(ctx, a.name, a.image)
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

    if head in _ALIAS_TO_WS_VERB:
        # Optional trailing NAME overrides the default.
        name = None
        verb_rest = rest
        # For verbs that take no further positional args, a lone trailing
        # token is an explicit workspace name (`credp enter myproj`).
        if head in {"enter", "start", "stop", "delete", "apply", "inspect", "logs"}:
            if rest:
                name = rest[0]
        _run_ws_verb(ctx, name, [head], trailing)
        return

    fail(f"unknown command '{head}'")


# ---- main --------------------------------------------------------------------


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
        elif head == "list":
            do_list(ctx, rest[0] if rest else None)
        elif head == "current":
            do_current(ctx)
        elif head in ("injector", "provider"):
            _dispatch_def(ctx, head, rest)
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


def _dispatch_def(ctx: Ctx, kind: str, rest: list[str]) -> None:
    if not rest:
        fail(f"usage: credproxy {kind} {{scaffold NAME|list}}")
    if rest[0] == "scaffold":
        if len(rest) != 2:
            fail(f"usage: credproxy {kind} scaffold NAME")
        do_scaffold(ctx, kind, rest[1])
    elif rest[0] == "list":
        do_def_list(ctx, kind)
    else:
        fail(f"unknown {kind} command '{rest[0]}'")


def _dispatch_dev(ctx: Ctx, rest: list[str], trailing: list[str]) -> None:
    if not rest:
        fail("usage: credproxy dev {build|test|reload}")
    sub = rest[0]
    if sub == "build":
        do_dev_build(ctx)
    elif sub == "test":
        test_args = rest[1:]  # e.g. ["--cli"] or ["--proxy"] or []
        cli_only = "--cli" in test_args
        proxy_only = "--proxy" in test_args
        do_dev_test(ctx, trailing, cli_only=cli_only, proxy_only=proxy_only)
    elif sub == "reload":
        do_dev_reload(ctx, rest[1] if len(rest) > 1 else None)
    else:
        fail(f"unknown dev command '{sub}'")
