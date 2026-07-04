"""The presentation layer: the one place that prints results.

Two sibling renderers fed by the core's structured data -- a human one and a
`--json` one -- selected by a per-process flag. Orthogonal to strict/loose:
the surface only sets the *default* format.

Conventions, in BOTH formats:
  - results go to stdout (human text, or one JSON object/array);
  - progress / announcements / prompts go to stderr with the `[credproxy] `
    prefix (so a `jq` pipeline reading stdout is never polluted);
  - errors in JSON mode serialize as a JSON object on stdout (don't break the
    pipeline); in human mode they go to stderr. Exit code is unchanged.

`OUT` holds the active renderer; `set_format()` installs it once in main().
"""
from __future__ import annotations

import json
import sys
from typing import NoReturn


# ---- progress / announcements (always stderr, both formats) -------------


def say(msg: str) -> None:
    """Progress/announcement to stderr with the prefix. Used as the core's
    `notify` callback and for default-resolution announcements."""
    print(f"[credproxy] {msg}", file=sys.stderr, flush=True)


# ---- the renderer ------------------------------------------------------


class Renderer:
    """Base/human renderer. Methods take structured data and emit text to
    stdout; the JSON subclass overrides them to emit JSON instead."""

    json = False

    # -- generic --
    def line(self, text: str) -> None:
        """A simple human status line (suppressed in JSON mode unless the
        command has a dedicated structured shape)."""
        print(text)

    def error(self, exc: Exception) -> None:
        say(str(exc))

    def result(self, obj) -> None:
        """A command's structured result already shaped as a dict/list for
        JSON. In human mode this is unused; commands call the specific
        renderer methods below."""
        # Human mode: nothing generic to print; specific methods handle it.
        pass

    # -- list --
    def workspace_list(self, rows: list[dict]) -> None:
        if not rows:
            print("no workspaces")
            return
        import os

        # Show the DIRECTORY column only when some workspace has an association,
        # so the common (unused) case renders exactly as before.
        show_dir = any(r.get("directory") for r in rows)
        # The `here` marker (and its second marker slot + legend) appear only
        # when cwd actually matches a workspace -- so a no-cwd survey renders
        # exactly as before, single-char `*`-only markers.
        show_here = any(r.get("here") for r in rows)
        home = os.path.expanduser("~")

        def short(d: str | None) -> str:
            if not d:
                return ""
            if d == home or d.startswith(home + os.sep):
                return "~" + d[len(home):]
            return d

        def marker(r: dict) -> str:
            # Two distinct, legended signals: `*` default, `→` current dir.
            # Both can land on one row (`*→`); the second slot exists only when
            # some row matches cwd, keeping the common case single-char.
            m = "*" if r["default"] else " "
            if show_here:
                m += "→" if r.get("here") else " "
            return m

        table = [["", "NAME", "STATUS", "IMAGE"] + (["DIRECTORY"] if show_dir else [])]
        for r in rows:
            row = [
                marker(r),
                r["name"],
                "running" if r["running"] else "stopped",
                r["image"],
            ]
            if show_dir:
                row.append(short(r.get("directory")))
            table.append(row)
        last = len(table[0]) - 1
        widths = [max(len(row[i]) for row in table) for i in range(last)]
        for row in table:
            cols = [f"{row[i]:<{widths[i]}}" for i in range(last)] + [row[last]]
            print("  ".join(cols))
        if show_here:
            say("markers: * default   → current directory")

    # -- info (centralized config & state) --
    def info(self, d: dict) -> None:
        import os

        home = os.path.expanduser("~")

        def short(p: str) -> str:
            if isinstance(p, str) and (p == home or p.startswith(home + os.sep)):
                return "~" + p[len(home):]
            return p

        print("credproxy — global configuration & state")
        print()
        if "default_workspace" in d:  # loose surface only
            print(f"  default workspace   {d['default_workspace'] or '(none)'}")
        print(f"  workspaces          {d['workspaces']}  (see `credproxy list`)")
        print()

        p = d["paths"]
        print("paths")
        print(f"  config              {short(p['config'])}")
        print(f"  state               {short(p['state'])}")
        if not p["profile_present"]:
            prof = f"{short(p['profile'])}  (absent)"
        elif d["profile_overrides"]:
            n = d["profile_overrides"]
            prof = f"{short(p['profile'])}  active · {n} override{'s' if n != 1 else ''}"
        else:
            prof = f"{short(p['profile'])}  (no overrides)"
        print(f"  profile             {prof}")
        print(f"  builtin             {short(p['builtin'])}")
        print(f"  proxy image         {d['proxy_image']}")
        print()

        print("registries            user · profile · builtin")
        for kind in ("injectors", "providers", "scripts", "presets"):
            t = d["registries"][kind]
            print(f"  {kind:<18}{t['user']}  ·  {t['profile']}  ·  {t['builtin']}")
        print()

        print("environment")
        for k, v in d["env"].items():
            print(f"  {k:<22}{short(v) if v else '(default)'}")

    # -- create / use / generic name ack --
    def created(self, name: str, path: str) -> None:
        print(f"created workspace '{name}' at {path}")
        say(f"edit {path}, then run `credproxy workspace {name} start`")

    def used(self, name: str) -> None:
        print(f"default workspace is now '{name}'")

    def bound_dir(self, name: str, directory: str) -> None:
        print(f"workspace '{name}' associated with {directory}")

    def current(self, workspace: str | None, source: str | None,
                default: str | None) -> None:
        # stdout stays just the name (clean for `$(credp current)`); the source
        # and any shadowed default are announced on stderr by the handler.
        print(workspace if workspace
              else "(no default workspace; run `credp use NAME`)")

    def deleted(self, name: str) -> None:
        print(f"deleted workspace '{name}'")

    def started(self, name: str) -> None:
        print(f"workspace '{name}' running")

    def recreated(self, name: str, include_proxy: bool = False,
                  reset_volumes: list[str] | None = None) -> None:
        scope = "workspace + proxy containers" if include_proxy \
            else "workspace container"
        extra = f" (reset volume(s): {', '.join(reset_volumes)})" \
            if reset_volumes else ""
        print(f"recreated {scope} for '{name}'{extra}; running")

    def stopped(self, name: str) -> None:
        print(f"workspace '{name}' stopped")

    def applied(self, name: str, result=None) -> None:
        """Render apply result. result is an ApplyResult dataclass or None."""
        if result is None or (not result.applied and not result.deferred):
            print(f"nothing to apply for workspace '{name}'")
            return
        for item in result.applied:
            print(f"applied: {item}")
        for item in result.deferred:
            print(f"deferred: {item}")

    def reloaded(self, name: str) -> None:
        print(f"reloaded proxy for workspace '{name}'")

    def scaffolded(self, kind: str, name: str, path: str) -> None:
        print(f"scaffolded {kind} '{name}' at {path}")

    # -- config --
    def config(self, data: dict) -> None:
        print(f"# {data['mode']} config  ({data['config_path']})")
        for k, v in data["config"].items():
            if isinstance(v, (dict, list)):
                import json as _json
                v = _json.dumps(v)
            elif v is None:
                v = "(unset)"
            elif isinstance(v, bool):
                v = "true" if v else "false"
            print(f"{k} = {v}")

    # -- inspect --
    def inspect(self, data: dict) -> None:
        print(f"workspace   {data['name']}")
        print(f"config      {data['config_path']}")
        c = data["config"]
        print(f"image       {c['image']}")
        print(f"home        {c['home']}")
        if c["mounts"]:
            mts = ", ".join(
                f"{m['source']}:{m['target']}" + (":ro" if m["readonly"] else "")
                for m in c["mounts"]
            )
            print(f"mounts      {mts}")
        if c["env"]:
            print(f"env         {', '.join(f'{k}={v}' for k, v in c['env'].items())}")
        if c["setup"]:
            print(f"setup       {len(c['setup'])} command(s)")
        print(f"proxy       {data['proxy_status'] or 'absent'}")
        print(f"workspace   {data['ws_status'] or 'absent'}")
        if data["host_port"] is not None:
            print(f"host port   127.0.0.1:{data['host_port']}")
        if data["bindings"]:
            print(f"bindings    {len(data['bindings'])}")
            for b in data["bindings"]:
                ph = b["placeholder"] or "(unmaterialized)"
                print(
                    f"  - {b['name']}: {b['injector']}/{b['provider']} "
                    f"-> {','.join(b['hosts'])}  [{ph}]"
                )
        else:
            print("bindings    none")
        if data.get("rules"):
            print(f"rules       {len(data['rules'])}")
            for r in data["rules"]:
                scope = ",".join(r["hosts"])
                m = "/".join(r["methods"]) if r.get("methods") else "*"
                p = r.get("path") or "*"
                act = r["action"] + (f":{r['script']}" if r.get("script") else "")
                vis = "" if r["visible"] else "  [hidden]"
                print(f"  - {r['name']}: {m} {scope}{p}  -> {act}{vis}")
        # Drift section.
        drift = data.get("drift", {})
        running = data.get("_running", False)
        changes = drift.get("changes", [])
        if drift.get("in_sync", True) and not changes:
            if data.get("ws_status") is None:
                print("drift       never started (no applied state)")
            else:
                print("drift       in sync")
        else:
            # Label bindings changes with "last applied" when stopped.
            bindings_qualifier = "" if running else " (last applied, not live)"
            print("drift")
            for ch in changes:
                item = ch["item"]
                if ch["kind"] == "container":
                    # Show before -> after for scalar fields.
                    applied = ch.get("applied")
                    configured = ch.get("configured")
                    if isinstance(applied, str) and isinstance(configured, str):
                        print(f"  {item}: {applied} -> {configured}")
                    else:
                        print(f"  {item}: changed")
                else:
                    print(f"  {item}{bindings_qualifier}")

    # -- binding add --
    def binding_added(self, name: str, ws: str, b: dict) -> None:
        from ..core.bindings import secret_display
        print(f"added binding '{name}' to workspace '{ws}'")
        print(f"  injector    {b['injector']}")
        print(f"  provider    {b['provider']}")
        print(f"  secret      {secret_display(b['secret'])}")
        print(f"  hosts       {', '.join(b['hosts'])}")
        print(f"  placeholder {b['placeholder'] or '(none)'}")
        if b.get("env"):
            print(f"  env         {b['env']}")

    def bindings_added(self, ws: str, rows: list[dict]) -> None:
        """Several bindings added in one command (a preset expansion). Human mode
        prints each; the JSON renderer emits a SINGLE object (one command -> one
        JSON value, not one per binding)."""
        for b in rows:
            self.binding_added(b["name"], ws, b)

    def binding_removed(self, name: str, ws: str) -> None:
        print(f"removed binding '{name}' from workspace '{ws}'")

    # -- mount add --
    def mount_added(self, ws: str, name: str, target: str, readonly: bool,
                    applied: bool = False) -> None:
        ro = " (read-only)" if readonly else ""
        print(f"added volume '{name}' -> {target}{ro} to workspace '{ws}'")
        if applied:
            print("  preserved the previous container's data; "
                  "recreated and running")
        else:
            say(f"run `credproxy workspace {ws} start` to apply "
                f"(recreates the container; the volume starts empty)")

    # -- binding list --
    def binding_list(self, ws: str, rows: list[dict]) -> None:
        from ..core.bindings import secret_display
        if not rows:
            print(f"no bindings in workspace '{ws}'")
            return
        header = ("NAME", "INJECTOR", "PROVIDER", "SECRET", "HOSTS", "ENV", "PLACEHOLDER")
        table = [header]
        for b in rows:
            table.append((
                b["name"], b["injector"], b["provider"], secret_display(b["secret"]),
                ",".join(b["hosts"]), b["env"] or "-", b["placeholder"] or "-",
            ))
        widths = [max(len(row[i]) for row in table) for i in range(len(header) - 1)]
        for row in table:
            cells = [f"{row[i]:<{widths[i]}}" for i in range(len(widths))]
            print("  ".join(cells) + "  " + row[-1])

    # -- binding test --
    def binding_test(self, results: list[dict]) -> None:
        for r in results:
            if r["ok"]:
                extra = f"; {r['note']}" if r.get("note") else ""
                print(
                    f"ok    {r['name']}  (provider {r['provider']}, "
                    f"value length {r['value_len']}{extra})"
                )
            else:
                print(f"FAIL  {r['name']}  (provider {r['provider']}): {r['error']}")

    # -- rule add / remove / list / test --
    def rule_added(self, name: str, ws: str, r: dict) -> None:
        print(f"added rule '{name}' to workspace '{ws}'")
        print(f"  hosts    {', '.join(r['hosts'])}")
        if r.get("methods"):
            print(f"  methods  {', '.join(r['methods'])}")
        if r.get("path"):
            print(f"  path     {r['path']}")
        print(f"  action   {r['action']}"
              + (f" ({r['script']})" if r.get("script") else ""))
        vis = "visible" if r["visible"] else "hidden (not enumerated to the workspace)"
        print(f"  {vis}")
        say(f"run `credproxy workspace {ws} start` (or `apply`) to push it to the proxy")

    def rule_removed(self, name: str, ws: str) -> None:
        print(f"removed rule '{name}' from workspace '{ws}'")

    def rule_list(self, ws: str, rows: list[dict]) -> None:
        if not rows:
            print(f"no rules in workspace '{ws}'")
            return
        header = ("NAME", "HOSTS", "METHODS", "PATH", "ACTION", "VISIBILITY")
        table = [header]
        for r in rows:
            table.append((
                r["name"], ",".join(r["hosts"]),
                ",".join(r["methods"]) if r.get("methods") else "*",
                r.get("path") or "*",
                r["action"] + (f":{r['script']}" if r.get("script") else ""),
                "visible" if r["visible"] else "HIDDEN",
            ))
        widths = [max(len(row[i]) for row in table) for i in range(len(header))]
        for row in table:
            print("  ".join(f"{row[i]:<{widths[i]}}" for i in range(len(header))).rstrip())

    @staticmethod
    def _rule_match_line(m: dict) -> str:
        detail = m["action"]
        if m.get("script"):
            # Offline the phase is unknown (no host Starlark) -> possibly-terminal.
            # --live carries the exact `phase` from the proxy's compiled scheme.
            if m.get("phase") == "response":
                detail = (f"script:{m['script']} "
                          f"(response-phase; may rewrite the response)")
            else:
                detail = f"script:{m['script']} (may block/respond/rewrite)"
        elif m["action"] in ("block", "respond") and m.get("status"):
            detail = f"{m['action']} {m['status']}"
        vis = "" if m["visible"] else "  [hidden]"
        cond = ("  (only if a preceding script doesn't block/respond)"
                if m.get("conditional") else "")
        return f"matched: {m['name']} → {detail}{vis}{cond}"

    def rule_test(self, method: str, url: str, matches: list[dict]) -> None:
        if not matches:
            print(f"no rule matches {method} {url}")
            return
        for m in matches:
            print(self._rule_match_line(m))

    def rule_test_live(self, method: str, url: str, result: dict) -> None:
        matches = result.get("matches", [])
        passthrough = "" if result.get("intercepted") else \
            "  (host not intercepted -- passthrough)"
        say("(live: what the running proxy would do, against its loaded config)")
        if not matches:
            print(f"no rule matches {method} {url}{passthrough}")
            return
        if passthrough:
            print(f"note:{passthrough.strip()}")
        for m in matches:
            print(self._rule_match_line(m))

    # -- injector / provider list --
    def def_list(self, kind: str, rows: list[dict]) -> None:
        if not rows:
            print(f"no {kind}s")
            return
        # Injectors carry a SCHEME column (so scripted injectors are visible as
        # such); providers carry a DESCRIPTION. Lay out the columns present.
        if any("scheme" in r for r in rows):
            cols = ("NAME", "SCHEME", "SOURCE")
            table = [cols] + [(r["name"], r.get("scheme", ""), r["source"]) for r in rows]
        elif any(r.get("description") for r in rows):
            cols = ("NAME", "SOURCE", "DESCRIPTION")
            table = [cols] + [(r["name"], r["source"], r.get("description", "")) for r in rows]
        else:
            cols = ("NAME", "SOURCE")
            table = [cols] + [(r["name"], r["source"]) for r in rows]
        widths = [max(len(row[i]) for row in table) for i in range(len(cols))]
        for row in table:
            print("  ".join(f"{row[i]:<{widths[i]}}" for i in range(len(cols))).rstrip())

    # -- scripted-injector scaffold / check --
    def scaffolded_script(self, name: str, injector_path: str,
                          script_path: str, family: str) -> None:
        print(f"scaffolded scripted injector '{name}' (family {family}):")
        print(f"  manifest  {injector_path}")
        print(f"  script    {script_path}")
        print(f"edit the script, then: credproxy injector check {name}")

    def injector_api(self, text: str) -> None:
        print(text, end="" if text.endswith("\n") else "\n")

    def injector_check(self, name: str, info: dict) -> None:
        status = "ok  " if info["ok"] else "FAIL"
        print(f"{status}  injector '{name}': {info['detail']}")
        if info.get("compiled"):
            if info["ok"]:
                print("  compiled cleanly in the proxy image")
            else:
                print(f"  compile error: {info['compile_error']}")
        elif info.get("scripted"):
            print("  (run with --compile to compile the .star in the proxy image)")

    # -- provider show --
    def provider_show(self, info: dict) -> None:
        print(f"provider: {info['name']}")
        print(f"  source:      {info['source']}")
        print(f"  path:        {info['path']}")
        if info.get("description"):
            print(f"  description: {info['description']}")
        if info.get("help"):
            print("  help:")
            for line in info["help"].rstrip("\n").splitlines():
                print(f"    {line}")
        elif not info.get("description"):
            print("  (this provider implements neither describe nor help)")

    # -- preset list --
    def preset_list(self, rows: list[dict]) -> None:
        if not rows:
            print("no presets")
            return
        print("Coordinated multi-binding sets. Use with:")
        print("  credproxy workspace NAME binding add --preset NAME "
              "--provider P --secret REF")
        for p in rows:
            print(f"\n{p['name']}  ({len(p['bindings'])} bindings)")
            for b in p["bindings"]:
                env = f"  env {b['env']}" if b.get("env") else ""
                hosts = ", ".join(b["hosts"])
                print(f"  {b['name']:<14} {b['injector']:<7} {hosts}{env}")


class JsonRenderer(Renderer):
    """Emits one JSON object/array per command result on stdout. Progress
    still goes to stderr (inherited `say`)."""

    json = True

    def _emit(self, obj) -> None:
        print(json.dumps(obj))

    def error(self, exc: Exception) -> None:
        self._emit({"error": {"type": type(exc).__name__, "message": str(exc)}})

    def workspace_list(self, rows: list[dict]) -> None:
        self._emit(rows)

    def info(self, d: dict) -> None:
        self._emit(d)

    def created(self, name: str, path: str) -> None:
        self._emit({"name": name, "config_path": path})

    def used(self, name: str) -> None:
        self._emit({"default": name})

    def bound_dir(self, name: str, directory: str) -> None:
        self._emit({"name": name, "directory": directory})

    def current(self, workspace: str | None, source: str | None,
                default: str | None) -> None:
        # `workspace`/`source` = the effective target a bare loose verb hits
        # (cwd-or-default); `default` = the `use` pointer. Both, unconflated.
        self._emit({"workspace": workspace, "source": source, "default": default})

    def deleted(self, name: str) -> None:
        self._emit({"deleted": name})

    def started(self, name: str) -> None:
        self._emit({"name": name, "running": True})

    def recreated(self, name: str, include_proxy: bool = False,
                  reset_volumes: list[str] | None = None) -> None:
        self._emit({"name": name, "recreated": True, "proxy": include_proxy,
                    "reset_volumes": reset_volumes or [], "running": True})

    def stopped(self, name: str) -> None:
        self._emit({"name": name, "running": False})

    def applied(self, name: str, result=None) -> None:
        if result is None:
            self._emit({"name": name, "applied": [], "deferred": []})
        else:
            self._emit({
                "name": name,
                "applied": list(result.applied),
                "deferred": list(result.deferred),
            })

    def reloaded(self, name: str) -> None:
        self._emit({"name": name, "reloaded": True})

    def scaffolded(self, kind: str, name: str, path: str) -> None:
        self._emit({"kind": kind, "name": name, "path": path})

    def config(self, data: dict) -> None:
        self._emit(data)

    def inspect(self, data: dict) -> None:
        # Strip the internal _running hint before emitting.
        out = {k: v for k, v in data.items() if not k.startswith("_")}
        self._emit(out)

    def binding_added(self, name: str, ws: str, b: dict) -> None:
        self._emit({"workspace": ws, "binding": b})

    def bindings_added(self, ws: str, rows: list[dict]) -> None:
        self._emit({"workspace": ws, "bindings": rows})

    def binding_removed(self, name: str, ws: str) -> None:
        self._emit({"workspace": ws, "removed": name})

    def mount_added(self, ws: str, name: str, target: str, readonly: bool,
                    applied: bool = False) -> None:
        self._emit({"workspace": ws,
                    "mount": {"volume": name, "target": target,
                              "readonly": readonly},
                    "applied": applied})

    def binding_list(self, ws: str, rows: list[dict]) -> None:
        self._emit({"workspace": ws, "bindings": rows})

    def binding_test(self, results: list[dict]) -> None:
        self._emit(results)

    def rule_added(self, name: str, ws: str, r: dict) -> None:
        self._emit({"workspace": ws, "rule": r})

    def rule_removed(self, name: str, ws: str) -> None:
        self._emit({"workspace": ws, "removed": name})

    def rule_list(self, ws: str, rows: list[dict]) -> None:
        self._emit({"workspace": ws, "rules": rows})

    def rule_test(self, method: str, url: str, matches: list[dict]) -> None:
        self._emit({"method": method, "url": url, "live": False,
                    "matches": matches})

    def rule_test_live(self, method: str, url: str, result: dict) -> None:
        # Same envelope as offline (`method`/`url`/`live`/`matches`) so a consumer
        # parses one shape; `--live` just adds `intercepted` and per-script `phase`.
        self._emit({"method": method, "url": url, "live": True,
                    "intercepted": result.get("intercepted"),
                    "matches": result.get("matches", [])})

    def def_list(self, kind: str, rows: list[dict]) -> None:
        self._emit(rows)

    def preset_list(self, rows: list[dict]) -> None:
        self._emit(rows)

    def provider_show(self, info: dict) -> None:
        self._emit(info)

    def scaffolded_script(self, name: str, injector_path: str,
                          script_path: str, family: str) -> None:
        self._emit({"name": name, "injector_path": injector_path,
                    "script_path": script_path, "family": family})

    def injector_api(self, text: str) -> None:
        self._emit({"reference": text})

    def injector_check(self, name: str, info: dict) -> None:
        self._emit({"name": name, **info})


# Active renderer, installed by set_format() in main().
OUT: Renderer = Renderer()


def set_format(as_json: bool) -> None:
    global OUT
    OUT = JsonRenderer() if as_json else Renderer()


# ---- failure -----------------------------------------------------------


def fail(msg_or_exc) -> NoReturn:
    """Render an error through the active renderer (JSON object on stdout in
    JSON mode, `[credproxy] ` line on stderr otherwise) and exit non-zero."""
    exc = msg_or_exc if isinstance(msg_or_exc, Exception) else UsageError(str(msg_or_exc))
    OUT.error(exc)
    sys.exit(1)


class UsageError(Exception):
    """Wraps a bare string message so JSON-mode errors still serialize with a
    type. Used for porcelain-level failures that aren't core exceptions."""
