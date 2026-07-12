"""Pack `[[option]]` whole-field values + loose-surface prompting (#59 v3).

An option supplies the ENTIRE value of a host-half field (a mount `bind`/`volume`
source, a `[[requires]]` path) via a STRUCTURAL `{ option = "id" }` marker -- never
a token inside a string. It resolves at expansion time: explicit `--opt id=value`
(or a template `[pack.options]` table) -> prompt (loose+TTY only) -> declared
`default` -> fail with the structured `{pack, missing}` error. The option value
is recorded in the `[[pack]]` reference (`[pack.options]`) and the resolved
whole value lands as literal config in the lock snapshot's expansion; the marker
never reaches the workspace TOML or the snapshot.
"""
from __future__ import annotations

import json
import textwrap

import pytest

from test_porcelain import _run, _run_loose


# ---- helpers -----------------------------------------------------------------


def _write_pack(name: str, toml: str):
    from credproxy_cli.core.paths import config_dir
    d = config_dir() / "packs"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.toml").write_text(textwrap.dedent(toml))
    return d / f"{name}.toml"


def _make_ws(name: str, content: str = 'image = "python:3.12-slim"\n'):
    from credproxy_cli.core.paths import workspaces_config_dir
    from credproxy_cli.core.model.workspace import Workspace
    wd = workspaces_config_dir()
    wd.mkdir(parents=True, exist_ok=True)
    (wd / f"{name}.toml").write_text(textwrap.dedent(content))
    return Workspace(name)


def _config_text(name: str) -> str:
    from credproxy_cli.core.paths import workspaces_config_dir
    return (workspaces_config_dir() / f"{name}.toml").read_text()


def _mount_source(name: str, target: str):
    """The resolved (expand_bind=False) source of the mount at `target`."""
    from credproxy_cli.core.model.resolver import resolve_workspace
    from credproxy_cli.core.model.workspace import Workspace
    cfg = resolve_workspace(Workspace(name)).config
    m = next(m for m in cfg["mounts"]
             if m["target"].rstrip("/") == target.rstrip("/"))
    return m.get("source") or m.get("name")


# A container-only pack whose mount source is supplied by a `sock_dir` option and
# whose `[[requires]]` path reuses the same option (the git-signing shape).
_OPT_PACK = """
    [[option]]
    id = "sock_dir"
    type = "string"
    default = "~/.ssh/credproxy-agent"
    description = "host directory holding the signing agent socket"

    [[mount]]
    bind = { option = "sock_dir" }
    target = "/ssh-agent"

    [[setup]]
    run = "echo configure git signing"
    order = 40

    [[requires]]
    kind = "path"
    path = { option = "sock_dir" }
    hint = "start the signing agent"
"""

# A pack whose option has NO default (required).
_OPT_REQUIRED = """
    [[option]]
    id = "sock_dir"
    type = "string"
    description = "host socket dir (required)"

    [[mount]]
    bind = { option = "sock_dir" }
    target = "/ssh-agent"
"""


# ---- parse / validate matrix -------------------------------------------------


def _load(name):
    from credproxy_cli.core.model.packs import get_pack
    return get_pack(name)


def test_option_parses_string_enum_bool(xdg):
    _write_pack("p", """
        [[option]]
        id = "s"
        type = "string"
        default = "x"
        [[option]]
        id = "e"
        type = "enum"
        choices = ["a", "b"]
        default = "b"
        [[option]]
        id = "flag"
        type = "bool"
        default = true
        [[mount]]
        bind = { option = "s" }
        target = "/x"
    """)
    spec = _load("p")
    by_id = {o.id: o for o in spec.options}
    assert by_id["s"].type == "string" and by_id["s"].default == "x"
    assert by_id["e"].choices == ("a", "b") and by_id["e"].default == "b"
    assert by_id["flag"].type == "bool" and by_id["flag"].default is True


def test_enum_default_must_be_member(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "e"
        type = "enum"
        choices = ["a", "b"]
        default = "zzz"
        [[mount]]
        bind = { option = "e" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="not one of the choices"):
        load_packs()


def test_enum_requires_nonempty_choices(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "e"
        type = "enum"
        [[mount]]
        bind = { option = "e" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="non-empty 'choices'"):
        load_packs()


def test_bool_default_must_be_bool(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "flag"
        type = "bool"
        default = "yes"
        [[mount]]
        bind = "/lit"
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="default must be a boolean"):
        load_packs()


def test_duplicate_option_id_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        [[option]]
        id = "x"
        type = "string"
        [[mount]]
        bind = { option = "x" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="duplicate .*option.* id"):
        load_packs()


def test_option_unknown_key_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        bogus = 1
        [[mount]]
        bind = { option = "x" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="unknown key"):
        load_packs()


def test_marker_in_container_half_field_rejected(xdg):
    """An option marker in a container-half field (mount `target`) is rejected."""
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "/host"
        [[mount]]
        bind = "/host"
        target = { option = "x" }
    """)
    with pytest.raises(ConfigError, match="container-half"):
        load_packs()


def test_marker_undefined_option_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "/host"
        [[mount]]
        bind = { option = "nope" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="undefined option 'nope'"):
        load_packs()


def test_marker_on_overlay_source_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "rel"
        [[mount]]
        overlay = { option = "x" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="overlay"):
        load_packs()


def test_bool_option_cannot_supply_a_source(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "flag"
        type = "bool"
        default = true
        [[mount]]
        bind = { option = "flag" }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="bool"):
        load_packs()


def test_malformed_marker_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "/host"
        [[mount]]
        bind = { option = "x", extra = 1 }
        target = "/x"
    """)
    with pytest.raises(ConfigError, match="extra key"):
        load_packs()


def test_option_only_pack_is_not_a_pack(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "y"
    """)
    with pytest.raises(ConfigError, match="needs at least one"):
        load_packs()


# ---- resolution order (core) -------------------------------------------------


def test_resolve_explicit_beats_default(xdg):
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("gitsign", _OPT_PACK)
    spec = _load("gitsign")
    vals, missing = resolve_options(spec, {"sock_dir": "/tmp/a"})
    assert missing == [] and vals == {"sock_dir": "/tmp/a"}


def test_resolve_default_used(xdg):
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("gitsign", _OPT_PACK)
    spec = _load("gitsign")
    vals, missing = resolve_options(spec, {})
    assert missing == [] and vals == {"sock_dir": "~/.ssh/credproxy-agent"}


def test_resolve_missing_required(xdg):
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("gitsign", _OPT_REQUIRED)
    spec = _load("gitsign")
    vals, missing = resolve_options(spec, {})
    assert vals == {} and [o.id for o in missing] == ["sock_dir"]


def test_resolve_unknown_opt_id_errors(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("gitsign", _OPT_PACK)
    spec = _load("gitsign")
    with pytest.raises(ConfigError, match="unknown option"):
        resolve_options(spec, {"nope": "x"})


def test_resolve_prompt_supplies_value(xdg):
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("gitsign", _OPT_REQUIRED)
    spec = _load("gitsign")
    vals, missing = resolve_options(
        spec, {}, prompt=lambda opt: "/prompted")
    assert missing == [] and vals == {"sock_dir": "/prompted"}


# ---- whole-field substitution: literal in the reference, marker gone ---------


def test_pack_add_records_literal_from_default(xdg):
    _write_pack("gitsign", _OPT_PACK)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "gitsign"])
    assert code == 0, out + err
    # The resolved value comes from the option default; the `[[pack]]` reference
    # records it explicitly in `[pack.options]` (the expansion lives in the lock).
    assert _mount_source("w", "/ssh-agent") == "~/.ssh/credproxy-agent"
    text = _config_text("w")
    assert "[pack.options]" in text and "credproxy-agent" in text


def test_pack_add_opt_overrides_default(xdg):
    _write_pack("gitsign", _OPT_PACK)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "gitsign",
                           "--opt", "sock_dir=/tmp/agent"])
    assert code == 0, out + err
    assert _mount_source("w", "/ssh-agent") == "/tmp/agent"
    assert "credproxy-agent" not in _config_text("w")


def test_bad_opt_syntax_fails(xdg):
    _write_pack("gitsign", _OPT_PACK)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "gitsign",
                           "--opt", "noeq"])
    assert code == 1
    assert "id=value" in (out + err)


# ---- missing required: strict + loose-no-TTY fail structured -----------------


def test_missing_required_strict_fails(xdg):
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "req"])
    assert code == 1
    assert "sock_dir" in (out + err)


def test_missing_required_json_shape(xdg):
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    code, out, err = _run(["--json", "workspace", "w", "pack", "add", "req"])
    assert code == 1
    obj = json.loads(out)["error"]
    assert obj["type"] == "PackOptionsError"
    assert obj["pack"] == "req"
    assert obj["missing"] == [
        {"id": "sock_dir", "type": "string", "description": "host socket dir (required)"}]


def test_missing_required_loose_no_tty_fails(xdg):
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    # loose but stdin is NOT a TTY -> no prompt, structured fail-closed.
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "req"],
                                stdin_text="", stdin_isatty=False)
    assert code == 1
    assert "sock_dir" in (out + err)


def test_missing_required_loose_tty_prompts(xdg, monkeypatch):
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(prompt_mod, "ask_option", lambda opt: "/from-prompt")
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "req"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert _mount_source("w", "/ssh-agent") == "/from-prompt"


def test_strict_never_prompts_even_with_tty(xdg, monkeypatch):
    """Prompting is loose-only: strict fails structured even on a TTY."""
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_option",
                        lambda opt: called.append(opt) or "/x")
    code, out, err = _run(["workspace", "w", "pack", "add", "req"],
                          stdin_text="", stdin_isatty=True)
    assert code == 1 and not called


# ---- template [pack.options] -----------------------------------------------


def _template(toml: str) -> None:
    from credproxy_cli.core.paths import config_dir
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "workspace.template.toml").write_text(textwrap.dedent(toml))


_MIN = 'image = "python:3.12-slim"\n'


def test_template_options_supply_value(xdg):
    _write_pack("gitsign", _OPT_PACK)
    _template(_MIN + textwrap.dedent("""
        [[pack]]
        name = "gitsign"
        [pack.options]
        sock_dir = "/tmpl/agent"
    """))
    code, out, err = _run(["workspace", "create", "proj"])
    assert code == 0, out + err
    assert _mount_source("proj", "/ssh-agent") == "/tmpl/agent"


def test_template_missing_required_option_fails_json(xdg):
    _write_pack("req", _OPT_REQUIRED)
    _template(_MIN + '\n[[pack]]\nname = "req"\n')
    code, out, err = _run(["--json", "workspace", "create", "proj"])
    assert code == 1
    obj = json.loads(out)["error"]
    assert obj["type"] == "PackOptionsError" and obj["pack"] == "req"
    # all-or-nothing: nothing written
    from credproxy_cli.core.paths import workspaces_config_dir
    assert not (workspaces_config_dir() / "proj.toml").exists()


def test_template_option_prompt_loose_tty(xdg, monkeypatch):
    _write_pack("req", _OPT_REQUIRED)
    _template(_MIN + '\n[[pack]]\nname = "req"\n')
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(prompt_mod, "ask_option", lambda opt: "/tmpl-prompt")
    code, out, err = _run_loose(["workspace", "create", "proj"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert _mount_source("proj", "/ssh-agent") == "/tmpl-prompt"


# ---- provider/secret prompting (decision 4) ----------------------------------


_BINDING_NODEFAULT = """
    [placeholder]
    prefix = "t_"
    length = 12
    charset = "alnumeric"

    [[part]]
    suffix = "api"
    injector = "bearer"
    hosts = ["api.svc.example.com"]
"""


def test_provider_secret_prompt_loose_tty(xdg, monkeypatch):
    _write_pack("svc", _BINDING_NODEFAULT)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(prompt_mod, "ask_provider", lambda default: "env")
    monkeypatch.setattr(prompt_mod, "ask_secret",
                        lambda provider, default, slot=None: "SVC_TOKEN")
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "svc"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    text = _config_text("w")
    assert '"env"' in text and '"SVC_TOKEN"' in text


def test_provider_secret_strict_never_prompts(xdg, monkeypatch):
    _write_pack("svc", _BINDING_NODEFAULT)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_provider",
                        lambda default: called.append("p") or "env")
    code, out, err = _run(["workspace", "w", "pack", "add", "svc"],
                          stdin_text="", stdin_isatty=True)
    assert code == 1 and not called
    assert "provider" in (out + err)


def test_secret_validate_at_prompt_loops(xdg, monkeypatch):
    """The real ask_secret validate loop: a bad ref fetch fails + loops, a good
    one reports length and returns. Drives the actual prompt via stdin."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setenv("GOOD_TOK", "abcdef")
    monkeypatch.delenv("BAD_TOK", raising=False)
    # First ref (BAD_TOK): validate=yes -> fetch fails -> loop. Second ref
    # (GOOD_TOK): validate=yes -> ok.
    import io
    import sys
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        "BAD_TOK\ny\nGOOD_TOK\ny\n"))
    ref = prompt_mod.ask_secret("env", None)
    assert ref == "GOOD_TOK"


# ---- refresh read-back -------------------------------------------------------


def test_eof_at_required_prompt_aborts_no_loop(xdg):
    """A genuine EOF (closed stdin) at a required-value prompt ABORTS cleanly
    rather than spinning forever re-prompting (S1). The real `ask_option` runs
    against an exhausted stdin (readline() -> "" every call)."""
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    # loose + TTY -> prompting is ON; stdin is empty so the first read is EOF.
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "req"],
                                stdin_text="", stdin_isatty=True)
    assert code == 1
    assert "EOF" in (out + err) or "aborted" in (out + err)
    # fail-closed: nothing stamped.
    assert "sock_dir" not in _config_text("w") or "option" not in _config_text("w")


def test_eof_distinct_from_empty_line(xdg, monkeypatch):
    """An ENTERED empty line (a bare Enter -> "\\n") at a required string prompt
    RE-PROMPTS; only a genuine EOF ("" with no newline) aborts. Drives the real
    `ask_option`: empty line, then a real value."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    import io
    import sys
    _write_pack("req", _OPT_REQUIRED)
    spec = _load("req")
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n/second-try\n"))
    val = prompt_mod.ask_option(spec.options[0])
    assert val == "/second-try"


# ---- S2: doctor report-all on a stale stamped option value -------------------


_STALE_ENUM = """
    [[option]]
    id = "mode"
    type = "enum"
    choices = ["{choices}"]

    [[mount]]
    bind = { option = "mode" }
    target = "/x"

    [[requires]]
    kind = "path"
    path = { option = "mode" }
    hint = "the chosen dir must exist"
"""

_GOOD_CMD = """
    [[mount]]
    bind = "/lit"
    target = "/g"

    [[requires]]
    kind = "command"
    command = "sh"
    hint = "install a shell"
"""



_NOPE_A = """
    [[mount]]
    bind = "/nope/a"
    target = "/a"
    [[setup]]
    run = "echo a"
    order = 1
"""

_NOPE_B = """
    [[mount]]
    bind = "/nope/b"
    target = "/b"
    [[setup]]
    run = "echo b"
    order = 2
"""


def test_multi_pack_create_with_missing_bind_sources(xdg):
    """A multi-`[[pack]]` template create succeeds even when entry 1 stamps a
    bind source that doesn't exist yet -- entry 2's validation re-load must not
    existence-check it (S4b)."""
    _write_pack("nopea", _NOPE_A)
    _write_pack("nopeb", _NOPE_B)
    _template(_MIN + textwrap.dedent("""
        [[pack]]
        name = "nopea"
        [[pack]]
        name = "nopeb"
    """))
    code, out, err = _run(["workspace", "create", "proj"])
    assert code == 0, out + err
    assert _mount_source("proj", "/a") == "/nope/a"
    assert _mount_source("proj", "/b") == "/nope/b"


def test_second_pack_add_with_missing_bind_source(xdg):
    """A second `pack add` on a workspace whose FIRST pack stamped a not-yet-
    existing bind source succeeds -- the add's validation re-load defers bind
    existence to `start` (S4c)."""
    _write_pack("nopea", _NOPE_A)
    _write_pack("nopeb", _NOPE_B)
    _make_ws("w")
    assert _run(["workspace", "w", "pack", "add", "nopea"])[0] == 0
    code, out, err = _run(["workspace", "w", "pack", "add", "nopeb"])
    assert code == 0, out + err
    assert _mount_source("w", "/a") == "/nope/a"
    assert _mount_source("w", "/b") == "/nope/b"


# ---- N1: --yes suppresses prompting ------------------------------------------


def test_yes_suppresses_prompt_for_required_option(xdg, monkeypatch):
    """Under `--yes` on loose+TTY, a required option must NOT prompt -- it takes
    the structured fail (explicit -> default -> fail), never asking (N1)."""
    _write_pack("req", _OPT_REQUIRED)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_option",
                        lambda opt: called.append(opt) or "/x")
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "req", "--yes"],
                                stdin_text="", stdin_isatty=True)
    assert code == 1 and not called
    assert "sock_dir" in (out + err)


def test_yes_takes_default_without_prompt(xdg, monkeypatch):
    """Under `--yes`, a defaulted option takes its default silently (no prompt)."""
    _write_pack("gitsign", _OPT_PACK)
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_option",
                        lambda opt: called.append(opt) or "/x")
    code, out, err = _run_loose(["workspace", "w", "pack", "add", "gitsign",
                                 "--yes"], stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert not called
    assert _mount_source("w", "/ssh-agent") == "~/.ssh/credproxy-agent"


# ---- N2: option-fed requires path renders {option=id}, never None ------------


def test_require_summary_renders_option_marker(xdg):
    from credproxy_cli.core.model.packs import get_pack, require_summary
    _write_pack("gitsign", _OPT_PACK)
    spec = get_pack("gitsign")
    rq = next(r for r in spec.requires if r.kind == "path")
    assert require_summary(rq)["path"] == "{option=sock_dir}"


def test_pack_list_json_shows_option_marker_path(xdg):
    _write_pack("gitsign", _OPT_PACK)
    code, out, err = _run(["--json", "pack", "list"])
    assert code == 0, out + err
    rows = json.loads(out)
    gs = next(r for r in rows if r["name"] == "gitsign")
    paths = [rq.get("path") for rq in gs["requires"]]
    assert "{option=sock_dir}" in paths
    assert None not in paths


# ---- N3: doctor splits requires-only vs. mount-fed-but-unrecoverable ----------


_OPT_MOUNT_AND_REQ = """
    [[option]]
    id = "sock_dir"
    type = "string"
    description = "host socket dir (required)"

    [[mount]]
    bind = { option = "sock_dir" }
    target = "/ssh-agent"

    [[requires]]
    kind = "path"
    path = { option = "sock_dir" }
    hint = "start the agent"
"""


def test_provider_prompt_reprompts_on_unknown(xdg, monkeypatch):
    """A free-typed name that isn't a registered provider re-prompts rather than
    returning an unresolvable name that errors out the command (N4)."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    import io
    import sys
    monkeypatch.setattr(sys, "stdin", io.StringIO("no-such-provider\nenv\n"))
    got = prompt_mod.ask_provider(None)
    assert got == "env"


# ---- N5: [pack . options] with TOML-legal spacing is stripped --------------


def test_template_pack_options_tolerates_spacing(xdg):
    _write_pack("gitsign", _OPT_PACK)
    _template(_MIN + textwrap.dedent("""
        [[pack]]
        name = "gitsign"
        [pack . options]
        sock_dir = "/spaced/agent"
    """))
    code, out, err = _run(["workspace", "create", "proj"])
    assert code == 0, out + err
    assert _mount_source("proj", "/ssh-agent") == "/spaced/agent"
    # The `[[pack]]` reference SURVIVES (config-v2), with a canonical
    # `[pack.options]` sub-table carrying the resolved value.
    text = _config_text("proj")
    assert "[[pack]]" in text and "[pack.options]" in text


# ---- N6: unreferenced option surfaced to the pack author ---------------------


_UNREF_OPT = """
    [[option]]
    id = "used"
    type = "string"
    default = "/host"

    [[option]]
    id = "unused"
    type = "bool"
    default = true

    [[mount]]
    bind = { option = "used" }
    target = "/x"
"""


def test_unreferenced_option_reported(xdg):
    from credproxy_cli.core.model.packs import describe_packs
    _write_pack("p", _UNREF_OPT)
    rows = describe_packs()
    p = next(r for r in rows if r["name"] == "p")
    assert p["unreferenced_options"] == ["unused"]


def test_pack_list_notes_unreferenced_option(xdg):
    _write_pack("p", _UNREF_OPT)
    code, out, err = _run(["pack", "list"])
    assert code == 0, out + err
    assert "inert" in out and "unused" in out


# ---- N7: env/setup marker rejection + enum/bool --opt coercion ---------------


def test_marker_in_env_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "v"
        [[mount]]
        bind = "/lit"
        target = "/x"
        [env]
        FOO = { option = "x" }
    """)
    with pytest.raises(ConfigError, match="env.FOO must be a non-empty string"):
        load_packs()


def test_marker_in_setup_run_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "v"
        [[setup]]
        run = { option = "x" }
        order = 1
    """)
    with pytest.raises(ConfigError, match="run` is required and must be a non-empty string"):
        load_packs()


def test_marker_in_setup_order_rejected(xdg):
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.model.packs import load_packs
    _write_pack("p", """
        [[option]]
        id = "x"
        type = "string"
        default = "v"
        [[setup]]
        run = "echo hi"
        order = { option = "x" }
    """)
    with pytest.raises(ConfigError, match="order` must be an integer"):
        load_packs()


_ENUM_BOOL = """
    [[option]]
    id = "mode"
    type = "enum"
    choices = ["/opt/a", "/opt/b"]
    [[option]]
    id = "flag"
    type = "bool"
    default = false
    [[mount]]
    bind = { option = "mode" }
    target = "/x"
    [[requires]]
    kind = "path"
    path = { option = "mode" }
    hint = "h"
"""


def test_opt_enum_rejects_non_choice(xdg):
    _write_pack("p", _ENUM_BOOL)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "p",
                           "--opt", "mode=zzz", "--opt", "flag=false"])
    assert code == 1
    assert "not one of the choices" in (out + err)


def test_opt_bool_rejects_garbage(xdg):
    _write_pack("p", _ENUM_BOOL)
    _make_ws("w")
    code, out, err = _run(["workspace", "w", "pack", "add", "p",
                           "--opt", "mode=/opt/a", "--opt", "flag=garbage"])
    assert code == 1
    assert "true/false" in (out + err)


def test_opt_bool_accepts_uppercase_true(xdg):
    from credproxy_cli.core.model.packs import resolve_options
    _write_pack("p", _ENUM_BOOL)
    spec = _load("p")
    vals, missing = resolve_options(spec, {"mode": "/opt/a", "flag": "TRUE"})
    assert missing == [] and vals["flag"] is True


def test_opt_duplicate_id_last_wins(xdg):
    from credproxy_cli.porcelain.cmd_pack import _parse_opt_flags
    out = _parse_opt_flags(["mode=/opt/a", "mode=/opt/b"])
    assert out["mode"] == "/opt/b"
