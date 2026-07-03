"""Rules: the workspace-owned, credential-free traffic-governance layer.

A *rule* is the sibling of a binding (see core/bindings.py). It governs a
request/response on an intercepted host -- block, stub, rewrite headers, or run a
sandboxed Starlark script -- and holds NO secret, provider, or placeholder. It
lives as a `[[rule]]` table in the workspace TOML.

This module mirrors core/bindings.py: parse + validate the `[[rule]]` array,
materialize a missing `name` back into the file (surgical text edit, reusing the
array-depth-aware block machinery in bindings.py), append/remove a rule block,
and map rules onto the proxy wire shape (`{"rules": [...]}`). Validation mirrors
proxy/config.py so a bad rule fails at `rule add`, not only at push. The matcher
(`match_rules`) is the CLI half of the wire-parity contract with proxy/rules.py
(host globs via hostmatch, path globs via pathmatch), and powers `rule test`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Callable

from . import hostmatch, pathmatch
from .bindings import (
    _atomic_write_text,
    _block_spans,
    _insert_line_in_block,
    _toml_key,
    _toml_str,
)
from .errors import ConfigError, CredproxyError
from .workspace import Workspace

import tomllib

Notify = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


ACTIONS = ("block", "respond", "rewrite", "script")
_TERMINAL_ACTIONS = ("block", "respond")
# Fields allowed per action (plus the common set); an unexpected field is a
# validation error, mirroring proxy/config._RULE_ACTION_FIELDS. NOTE the one
# intentional asymmetry: the proxy's `script` set also allows `script_source`
# (the .star body), which the CLI never writes in TOML -- it is injected at
# wire time by rule_wire_entries (via find_script). So this TOML-facing set
# stays {script, api}; don't "sync" script_source in here.
_COMMON_FIELDS = frozenset({"name", "hosts", "methods", "path", "action", "visible"})
_ACTION_FIELDS = {
    "block": frozenset({"status"}),
    "respond": frozenset({"status", "body", "headers"}),
    "rewrite": frozenset({"set_headers", "remove_headers",
                          "resp_set_headers", "resp_remove_headers"}),
    "script": frozenset({"script", "api"}),
}
# Per-family default for the `visible` flag (mirrors proxy).
_VISIBLE_DEFAULT = {"block": True, "respond": True, "rewrite": False,
                    "script": False}
# A rewrite may not touch the request authority (Host/:authority): binding
# selection happens on the pre-rewrite host, so it would ship the injected
# credential under a different host -- a scope escape. Mirrors
# proxy/config._FORBIDDEN_REWRITE_HEADERS; rejected at `rule add`.
_FORBIDDEN_REWRITE_HEADERS = frozenset({"host", ":authority"})

# The `[[rule]]` table header (a trailing comment is allowed) -- fed to the
# generic, array-depth-aware block machinery shared with bindings.
_RULE_HEADER_RE = re.compile(r"^\s*\[\[\s*rule\s*\]\]\s*(#.*)?$")
# A `[rule.xxx]` child sub-table (e.g. a hand-written `[rule.headers]` instead of
# the inline table we render): it belongs to the preceding `[[rule]]` element, so
# the block machinery must fold it into that element's span (not end the block at
# it) -- else `rule remove` orphans it.
_RULE_CHILD_RE = re.compile(r"^\s*\[\s*rule\.[^\[\]\n]*\]\s*(#.*)?$")


@dataclass(frozen=True)
class Rule:
    name: str | None                       # None until materialized
    hosts: tuple[str, ...]
    action: str
    methods: tuple[str, ...] | None = None
    path: str | None = None
    visible: bool | None = None            # None -> per-family default
    status: int | None = None
    body: str | None = None
    headers: dict | None = None
    set_headers: dict | None = None
    remove_headers: tuple[str, ...] | None = None
    resp_set_headers: dict | None = None
    resp_remove_headers: tuple[str, ...] | None = None
    script: str | None = None
    api: int = 1

    @property
    def effective_visible(self) -> bool:
        return self.visible if self.visible is not None \
            else _VISIBLE_DEFAULT[self.action]


# ---- parsing / validation ---------------------------------------------------


def _as_str_map(value, source: str, where: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{source}: {where} must be a table of string->string")
    for k, v in value.items():
        if not isinstance(k, str) or not k or not isinstance(v, str):
            raise ConfigError(f"{source}: {where} must map non-empty header "
                              f"names to string values")
    return dict(value)


def _as_str_list(value, source: str, where: str) -> tuple:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ConfigError(f"{source}: {where} must be an array of non-empty strings")
    return tuple(value)


def _parse_rules(raw: dict, source: str) -> list[Rule]:
    """Parse the `[[rule]]` array from a raw TOML dict. Validates field
    types/presence and rejects fields not valid for the action, but NOT
    cross-rule uniqueness (see `validate`)."""
    items = raw.get("rule") or []
    if not isinstance(items, list):
        raise ConfigError(f"{source}: `rule` must be an array of tables")
    out: list[Rule] = []
    for i, r in enumerate(items):
        if not isinstance(r, dict):
            raise ConfigError(f"{source}: rule[{i}] must be a table")
        where = f"rule[{i}]"

        action = r.get("action")
        if action not in ACTIONS:
            raise ConfigError(f"{source}: {where}.action must be one of "
                              f"{', '.join(ACTIONS)} (got {action!r})")
        allowed = _COMMON_FIELDS | _ACTION_FIELDS[action]
        extra = set(r) - allowed
        if extra:
            raise ConfigError(f"{source}: {where} has field(s) not valid for "
                              f"action '{action}': {', '.join(sorted(extra))}")

        hosts = r.get("hosts")
        if not isinstance(hosts, list) or not hosts \
                or not all(isinstance(h, str) and h for h in hosts):
            raise ConfigError(
                f"{source}: {where}.hosts is required (non-empty array of strings)")

        name = r.get("name")
        if name is not None and (not isinstance(name, str) or not name):
            raise ConfigError(f"{source}: {where}.name must be a non-empty string")

        methods = r.get("methods")
        if methods is None:
            method_tuple = None
        else:
            method_list = _as_str_list(methods, source, f"{where}.methods")
            if not method_list:
                raise ConfigError(f"{source}: {where}.methods must be a non-empty "
                                  f"array (omit it entirely to match all methods)")
            method_tuple = tuple(m.upper() for m in method_list)

        path = r.get("path")
        if path is not None:
            if not isinstance(path, str):
                raise ConfigError(f"{source}: {where}.path must be a string")
            perr = pathmatch.validate_path(path)
            if perr:
                raise ConfigError(f"{source}: {where}.path: {perr}")

        visible = r.get("visible")
        if visible is not None and not isinstance(visible, bool):
            raise ConfigError(f"{source}: {where}.visible must be a boolean")

        kwargs = {}
        if action == "block":
            kwargs["status"] = _parse_status(r, source, where, default=403)
        elif action == "respond":
            if r.get("status") is None:
                raise ConfigError(f"{source}: {where} action 'respond' requires "
                                  f"a 'status'")
            kwargs["status"] = _parse_status(r, source, where, default=None)
            body = r.get("body")
            if body is not None and not isinstance(body, str):
                raise ConfigError(f"{source}: {where}.body must be a string")
            kwargs["body"] = body
            headers = r.get("headers")
            kwargs["headers"] = (_as_str_map(headers, source, f"{where}.headers")
                                 if headers is not None else None)
        elif action == "rewrite":
            sh, rh = r.get("set_headers"), r.get("remove_headers")
            rsh, rrh = r.get("resp_set_headers"), r.get("resp_remove_headers")
            if sh is None and rh is None and rsh is None and rrh is None:
                raise ConfigError(f"{source}: {where} action 'rewrite' needs at "
                                  f"least one of set_headers/remove_headers/"
                                  f"resp_set_headers/resp_remove_headers")
            kwargs["set_headers"] = (_as_str_map(sh, source, f"{where}.set_headers")
                                     if sh is not None else None)
            kwargs["remove_headers"] = (_as_str_list(rh, source, f"{where}.remove_headers")
                                        if rh is not None else None)
            kwargs["resp_set_headers"] = (_as_str_map(rsh, source, f"{where}.resp_set_headers")
                                          if rsh is not None else None)
            kwargs["resp_remove_headers"] = (_as_str_list(rrh, source, f"{where}.resp_remove_headers")
                                             if rrh is not None else None)
        elif action == "script":
            script = r.get("script")
            if not isinstance(script, str) or not script:
                raise ConfigError(f"{source}: {where} action 'script' requires a "
                                  f"'script' name")
            kwargs["script"] = script
            api = r.get("api", 1)
            if not isinstance(api, int) or isinstance(api, bool):
                raise ConfigError(f"{source}: {where}.api must be an integer")
            kwargs["api"] = api

        out.append(Rule(
            name=name,
            hosts=tuple(hosts),
            action=action,
            methods=method_tuple,
            path=path,
            visible=visible,
            **kwargs,
        ))
    return out


def _parse_status(r: dict, source: str, where: str, default):
    status = r.get("status", default)
    if status is default and default is not None:
        return default
    if not isinstance(status, int) or isinstance(status, bool) \
            or not (100 <= status <= 599):
        raise ConfigError(f"{source}: {where}.status must be an integer HTTP "
                          f"status (100-599), got {status!r}")
    return status


def _sanitize(token: str) -> str:
    """A host/action fragment reduced to the name charset for auto-naming."""
    s = re.sub(r"[^a-z0-9]+", "-", token.lower()).strip("-")
    return s or "rule"


def _auto_name(rule: Rule, taken: set[str]) -> str:
    """`<action>-<first-host>`, with a numeric suffix on collision."""
    base = f"{rule.action}-{_sanitize(rule.hosts[0])}"
    if base not in taken:
        return base
    i = 2
    while f"{base}-{i}" in taken:
        i += 1
    return f"{base}-{i}"


def _with_auto_names(rules: list[Rule]) -> list[Rule]:
    taken = {r.name for r in rules if r.name}
    out: list[Rule] = []
    for r in rules:
        if r.name is None:
            name = _auto_name(r, taken)
            taken.add(name)
            out.append(replace(r, name=name))
        else:
            out.append(r)
    return out


def validate(rules: list[Rule], source: str) -> None:
    """Cross-rule validation: unique names; valid host/path globs; a script
    action's `.star` must resolve. Mirrors proxy/config._load_rules so a bad rule
    is caught at `rule add`. Names must already be materialized (non-None)."""
    names: set[str] = set()
    for r in rules:
        if r.name is None:
            raise ConfigError(f"{source}: a rule is missing a name")
        if r.name in names:
            raise ConfigError(f"{source}: duplicate rule name '{r.name}'")
        names.add(r.name)

        for host in r.hosts:
            if hostmatch.is_pattern(host):
                err = hostmatch.validate_pattern(host)
                if err:
                    raise ConfigError(f"{source}: rule '{r.name}': {err}")

        if r.path is not None:
            perr = pathmatch.validate_path(r.path)
            if perr:
                raise ConfigError(f"{source}: rule '{r.name}': {perr}")

        if r.methods is not None and not r.methods:
            raise ConfigError(f"{source}: rule '{r.name}': methods must be a "
                              f"non-empty array (omit it to match all methods)")

        # Per-action field validation. _parse_rules does this for the load path,
        # but `rule add` constructs a Rule directly and only calls validate(), so
        # repeat it here or a bad rule (e.g. --status 999) writes a file that then
        # fails every subsequent load.
        if r.status is not None and (not isinstance(r.status, int)
                                     or isinstance(r.status, bool)
                                     or not (100 <= r.status <= 599)):
            raise ConfigError(f"{source}: rule '{r.name}': status must be an "
                              f"integer HTTP status (100-599), got {r.status!r}")
        if r.action == "respond" and r.status is None:
            raise ConfigError(f"{source}: rule '{r.name}': action 'respond' "
                              f"requires a status")
        if r.action == "rewrite" and not (r.set_headers or r.remove_headers
                                          or r.resp_set_headers or r.resp_remove_headers):
            raise ConfigError(f"{source}: rule '{r.name}': action 'rewrite' needs "
                              f"at least one header operation")
        if r.action == "rewrite":
            for hn in list(r.set_headers or {}) + list(r.remove_headers or ()):
                if hn.lower() in _FORBIDDEN_REWRITE_HEADERS:
                    raise ConfigError(
                        f"{source}: rule '{r.name}': a rewrite may not touch the "
                        f"request authority header '{hn}' (Host/:authority) -- it "
                        f"would send the injected credential under a different "
                        f"host than the binding is scoped to")
        if r.action == "script":
            if not r.script:
                raise ConfigError(f"{source}: rule '{r.name}': action 'script' "
                                  f"requires a script name")
            from .scripts import find_script
            try:
                find_script(r.script)
            except CredproxyError as e:
                raise ConfigError(f"{source}: rule '{r.name}': {e}")


def load_rules(ws: Workspace) -> list[Rule]:
    """Parse + validate the workspace's `[[rule]]` array (auto-names filled
    in-memory). Raises ConfigError on failure."""
    raw = tomllib.loads(ws.config_path.read_text())
    source = str(ws.config_path)
    rules = _with_auto_names(_parse_rules(raw, source))
    validate(rules, source)
    return rules


# ---- materialization + imperative edits -------------------------------------


def materialize_rules(ws: Workspace, notify: Notify = _noop) -> list[Rule]:
    """Ensure every rule has a static `name` on disk (rules have no placeholder),
    writing a generated name back into that rule's block via a surgical edit.
    Idempotent; returns the parsed + validated rules with names filled."""
    text = ws.config_path.read_text()
    raw = tomllib.loads(text)
    source = str(ws.config_path)
    rules = _parse_rules(raw, source)

    taken = {r.name for r in rules if r.name}
    resolved: list[Rule] = []
    for r in rules:
        name = r.name
        if name is None:
            name = _auto_name(r, taken)
            taken.add(name)
        resolved.append(replace(r, name=name))

    changed = False
    for idx, (orig, res) in enumerate(zip(rules, resolved)):
        if orig.name is None:
            text = _insert_line_in_block(text, idx, f'name = {_toml_str(res.name)}',
                                         header_re=_RULE_HEADER_RE,
                                         child_re=_RULE_CHILD_RE)
            notify(f"materialized name '{res.name}' for rule [{idx}]")
            changed = True

    if changed:
        _atomic_write_text(ws.config_path, text)
    validate(resolved, source)
    return resolved


def _render_rule_block(rule: Rule) -> str:
    """Render a fully-formed `[[rule]]` block (leading blank line), escaping
    every interpolated value so it round-trips as valid TOML."""
    def _inline_map(d: dict) -> str:
        inner = ", ".join(f'{_toml_key(k)} = {_toml_str(v)}' for k, v in d.items())
        return "{ " + inner + " }"

    def _array(xs) -> str:
        return "[" + ", ".join(_toml_str(x) for x in xs) + "]"

    lines = ["", "[[rule]]", f'name    = {_toml_str(rule.name)}',
             "hosts   = " + _array(rule.hosts)]
    if rule.methods is not None:
        lines.append("methods = " + _array(rule.methods))
    if rule.path is not None:
        lines.append(f'path    = {_toml_str(rule.path)}')
    lines.append(f'action  = {_toml_str(rule.action)}')
    if rule.visible is not None:
        lines.append(f'visible = {"true" if rule.visible else "false"}')
    if rule.status is not None:
        lines.append(f'status  = {rule.status}')
    if rule.body is not None:
        lines.append(f'body    = {_toml_str(rule.body)}')
    if rule.headers is not None:
        lines.append(f'headers = {_inline_map(rule.headers)}')
    if rule.set_headers is not None:
        lines.append(f'set_headers = {_inline_map(rule.set_headers)}')
    if rule.remove_headers is not None:
        lines.append('remove_headers = ' + _array(rule.remove_headers))
    if rule.resp_set_headers is not None:
        lines.append(f'resp_set_headers = {_inline_map(rule.resp_set_headers)}')
    if rule.resp_remove_headers is not None:
        lines.append('resp_remove_headers = ' + _array(rule.resp_remove_headers))
    if rule.script is not None:
        lines.append(f'script  = {_toml_str(rule.script)}')
    if rule.action == "script" and rule.api != 1:
        lines.append(f'api     = {rule.api}')
    return "\n".join(lines) + "\n"


def append_rule(ws: Workspace, rule: Rule) -> None:
    """Append a single `[[rule]]` block to the workspace TOML."""
    text = ws.config_path.read_text()
    if text and not text.endswith("\n"):
        text += "\n"
    _atomic_write_text(ws.config_path, text + _render_rule_block(rule))


def remove_rule(ws: Workspace, name: str) -> None:
    """Remove the named rule's `[[rule]]` block via a surgical text edit."""
    text = ws.config_path.read_text()
    raw = tomllib.loads(text)
    rules = _with_auto_names(_parse_rules(raw, str(ws.config_path)))
    target = next((i for i, r in enumerate(rules) if r.name == name), None)
    if target is None:
        raise ConfigError(f"rule '{name}' not found in {ws.config_path}")
    lines = text.splitlines(keepends=True)
    spans = _block_spans(text, _RULE_HEADER_RE, _RULE_CHILD_RE)
    start, end = spans[target]
    if start > 0 and lines[start - 1].strip() == "":
        start -= 1
    del lines[start:end]
    _atomic_write_text(ws.config_path, "".join(lines))


# ---- matching (the CLI half of the wire-parity contract) --------------------


def _matches(rule: Rule, method: str, host: str, path: str) -> bool:
    h = host.lower()
    host_ok = False
    for pat in rule.hosts:
        if hostmatch.is_pattern(pat):
            if hostmatch.compile_pattern(pat.lower()).fullmatch(h):
                host_ok = True
                break
        elif pat.lower() == h:
            host_ok = True
            break
    if not host_ok:
        return False
    if rule.methods is not None and method.upper() not in rule.methods:
        return False
    if rule.path is not None:
        if not pathmatch.compile_path(rule.path).fullmatch(path.split("?", 1)[0]):
            return False
    return True


@dataclass(frozen=True)
class RuleMatch:
    name: str
    action: str
    terminal: bool     # block/respond (or a script, which MAY be terminal)
    visible: bool


def match_rules(rules: list[Rule], method: str, host: str, path: str) -> list[RuleMatch]:
    """The rules that match a request, in declaration order, up to and including
    the first terminal one. A `script` is reported as possibly-terminal (the
    proxy decides at runtime), so evaluation does not continue past it -- the
    dry-run can't know what the script will do."""
    out: list[RuleMatch] = []
    for r in rules:
        if not _matches(r, method, host, path):
            continue
        terminal = r.action in _TERMINAL_ACTIONS or r.action == "script"
        out.append(RuleMatch(r.name, r.action, terminal, r.effective_visible))
        if terminal:
            break
    return out


# ---- wire mapping (push path) -----------------------------------------------


def rule_wire_entries(rules: list[Rule]) -> list[dict]:
    """Produce the proxy `rules` wire entries. A script rule embeds its `.star`
    SOURCE (the push model -- the proxy compiles what it is given). `visible` is
    sent only when explicitly set, so the proxy applies the per-family default."""
    from .scripts import find_script

    entries: list[dict] = []
    for r in rules:
        entry: dict = {"name": r.name, "hosts": list(r.hosts), "action": r.action}
        if r.methods is not None:
            entry["methods"] = list(r.methods)
        if r.path is not None:
            entry["path"] = r.path
        if r.visible is not None:
            entry["visible"] = r.visible
        if r.status is not None:
            entry["status"] = r.status
        if r.body is not None:
            entry["body"] = r.body
        if r.headers is not None:
            entry["headers"] = r.headers
        if r.set_headers is not None:
            entry["set_headers"] = r.set_headers
        if r.remove_headers is not None:
            entry["remove_headers"] = list(r.remove_headers)
        if r.resp_set_headers is not None:
            entry["resp_set_headers"] = r.resp_set_headers
        if r.resp_remove_headers is not None:
            entry["resp_remove_headers"] = list(r.resp_remove_headers)
        if r.action == "script":
            entry["script"] = r.script
            entry["script_source"] = find_script(r.script).source
            entry["api"] = r.api
        entries.append(entry)
    return entries


def rules_fingerprint_items(rules: list[Rule]) -> list[dict]:
    """Stable wire-metadata items for the config fingerprint (mirrors
    rule_wire_entries, incl. the script source, so a rule/script change
    re-pushes). Returned as a list for the caller to fold into the combined
    binding+rule fingerprint.

    Rules are NOT sorted (unlike bindings): evaluation is strict DECLARATION
    ORDER -- first-terminal-wins, cumulative rewrites -- so a reorder changes
    behavior and MUST change the fingerprint (re-push on the next start/enter)."""
    return rule_wire_entries(rules)


def combined_fingerprint(bindings, rules: list[Rule]) -> str:
    """A single stable hash over the FULL pushed config (bindings + rules), so a
    change to either re-pushes. Folds bindings.`_fingerprint_items` and this
    module's rule items; equals bindings.config_fingerprint when there are no
    rules only up to the wrapper shape (the push path always uses this)."""
    import hashlib
    import json as _json

    from .bindings import _fingerprint_items

    blob = _json.dumps(
        {"bindings": _fingerprint_items(bindings),
         "rules": rules_fingerprint_items(rules)},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()
