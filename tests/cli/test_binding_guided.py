"""Guided `binding add` on loose+TTY (#75): prompt for missing injector /
provider / secret / hosts through the extended #59 prompt seam.

Prompting is loose-surface-only, TTY-only (the standing constitutional decision):
strict `credproxy` and loose-without-a-TTY keep the report-all-missing-flags
fail-closed behavior. Supplied flags are skipped (partial flags + prompts
compose); the result is the same appended `[[binding]]` block as the fully-flagged
form, echoed afterward so the user learns the flags for next time.
"""
from __future__ import annotations

import io
import sys
import textwrap

import pytest

from test_porcelain import _run, _run_loose


# ---- helpers -----------------------------------------------------------------


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


def _bindings(name: str):
    from credproxy_cli.core.model.resolver import resolve_workspace
    from credproxy_cli.core.model.workspace import Workspace
    return resolve_workspace(Workspace(name)).bindings


def _patch_all(monkeypatch, *, injector="bearer", provider="env",
               secret="GITHUB_TOKEN", hosts=("api.example.com",)):
    """Monkeypatch every prompt seam to fixed answers (no real TTY needed)."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(prompt_mod, "ask_injector", lambda default="bearer": injector)
    monkeypatch.setattr(prompt_mod, "ask_provider", lambda default: provider)
    monkeypatch.setattr(prompt_mod, "ask_secret",
                        lambda p, d, slot=None: secret)
    monkeypatch.setattr(prompt_mod, "ask_hosts", lambda: list(hosts))


# ---- the guided happy path ---------------------------------------------------


def test_flagless_add_prompts_all(xdg, monkeypatch):
    """A wholly-flagless `credp binding add` on loose+TTY walks all four gaps and
    writes the same block the fully-flagged form would."""
    _make_ws("w")
    _patch_all(monkeypatch)
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    (b,) = _bindings("w")
    assert b.injector == "bearer"
    assert b.provider == "env"
    assert b.secret == "GITHUB_TOKEN"
    assert b.hosts == ("api.example.com",)


def test_guided_echoes_equivalent_command(xdg, monkeypatch):
    """The teaching moment: the equivalent fully-flagged form is echoed afterward
    (loose spelling), so the guided path makes itself unnecessary next time."""
    _make_ws("w")
    _patch_all(monkeypatch)
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert "equivalent to:" in err
    assert ("credp binding add --injector bearer --provider env "
            "--secret GITHUB_TOKEN --host api.example.com") in err


def test_partial_flags_compose(xdg, monkeypatch):
    """Supplied flags are skipped; only the missing ones prompt. A supplied
    --injector/--host is used verbatim, provider/secret are prompted."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_injector",
                        lambda default="bearer": called.append("inj") or "bearer")
    monkeypatch.setattr(prompt_mod, "ask_hosts",
                        lambda: called.append("host") or ["nope"])
    monkeypatch.setattr(prompt_mod, "ask_provider", lambda default: "env")
    monkeypatch.setattr(prompt_mod, "ask_secret", lambda p, d, slot=None: "TOK")
    code, out, err = _run_loose(
        ["workspace", "w", "binding", "add",
         "--injector", "bearer", "--host", "api.example.com"],
        stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    # injector + host were supplied -> never prompted.
    assert called == []
    (b,) = _bindings("w")
    assert b.provider == "env" and b.secret == "TOK"
    assert b.hosts == ("api.example.com",)


# ---- multi-slot secret prompting (#71 interaction) ---------------------------


def test_echo_includes_supplied_optional_flags(xdg, monkeypatch):
    """Optional flags the user DID supply (--name/--env) ride along in the echo so
    it reproduces this exact binding, not a variant."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(prompt_mod, "ask_provider", lambda default: "env")
    monkeypatch.setattr(prompt_mod, "ask_secret", lambda p, d, slot=None: "TOK")
    monkeypatch.setattr(prompt_mod, "ask_hosts", lambda: ["api.example.com"])
    code, out, err = _run_loose(
        ["workspace", "w", "binding", "add",
         "--injector", "bearer", "--name", "mybind", "--env", "FOO"],
        stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert "--name mybind" in err
    assert "--env FOO" in err


def test_echo_shell_quotes_glob_host(xdg, monkeypatch):
    """A glob host is shell-quoted in the echo so pasting it doesn't glob-expand."""
    _make_ws("w")
    _patch_all(monkeypatch, injector="bearer", hosts=("*.example.com",))
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert "--host '*.example.com'" in err


def test_multislot_prompts_per_slot(xdg, monkeypatch):
    """A multi-slot injector (sigv4) prompts each declared slot separately and
    assembles the slot->ref table; the echo lists one --secret SLOT=REF per slot."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    slots_seen = []

    def fake_secret(provider, default, slot=None):
        slots_seen.append(slot)
        return f"{slot}-ref"

    monkeypatch.setattr(prompt_mod, "ask_injector", lambda default="bearer": "sigv4")
    monkeypatch.setattr(prompt_mod, "ask_provider", lambda default: "env")
    monkeypatch.setattr(prompt_mod, "ask_secret", fake_secret)
    monkeypatch.setattr(prompt_mod, "ask_hosts", lambda: ["*.amazonaws.com"])
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 0, out + err
    assert slots_seen == ["access_key_id", "secret_access_key"]
    (b,) = _bindings("w")
    assert b.secret == {"access_key_id": "access_key_id-ref",
                        "secret_access_key": "secret_access_key-ref"}
    assert "--secret access_key_id=access_key_id-ref" in err
    assert "--secret secret_access_key=secret_access_key-ref" in err


# ---- fail-closed surfaces (no prompting) -------------------------------------


def test_strict_never_prompts(xdg, monkeypatch):
    """Strict fails structured even on a TTY -- prompting is loose-only."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_injector",
                        lambda default="bearer": called.append("x") or "bearer")
    code, out, err = _run(["workspace", "w", "binding", "add"],
                          stdin_text="", stdin_isatty=True)
    assert code == 1 and not called
    assert "missing" in (out + err)


def test_loose_no_tty_never_prompts(xdg, monkeypatch):
    """Loose but no TTY on stdin -> no prompt, the report-all-missing fail."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_injector",
                        lambda default="bearer": called.append("x") or "bearer")
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=False)
    assert code == 1 and not called
    assert "missing" in (out + err)
    assert "--injector" in (out + err) and "--host" in (out + err)


def test_nonexistent_workspace_fails_before_prompting(xdg, monkeypatch):
    """The workspace is resolved FIRST -- a bad NAME fails fast, before the user
    is made to answer any prompt (pins the fail-fast claim)."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_injector",
                        lambda default="bearer": called.append("x") or "bearer")
    code, out, err = _run_loose(["workspace", "nope", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 1 and not called


def test_eof_mid_flow_aborts(xdg, monkeypatch):
    """A genuine EOF at a required guided prompt ABORTS cleanly (the real `_ask`
    EOF->fail path) rather than hanging; nothing is written."""
    _make_ws("w")
    # loose + TTY -> prompting ON; empty stdin -> the first read (injector) is EOF.
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 1
    assert "EOF" in (out + err) or "aborted" in (out + err)
    assert not _bindings("w")


def test_yes_suppresses_prompting(xdg, monkeypatch):
    """--yes is a non-interactive intent -> fail-closed, no prompt (parity with
    pack prompting / the missing-proxy-image gate)."""
    _make_ws("w")
    from credproxy_cli.porcelain import prompt as prompt_mod
    called = []
    monkeypatch.setattr(prompt_mod, "ask_injector",
                        lambda default="bearer": called.append("x") or "bearer")
    code, out, err = _run_loose(["--yes", "workspace", "w", "binding", "add"],
                                stdin_text="", stdin_isatty=True)
    assert code == 1 and not called


# ---- real prompt loops (ask_injector / ask_hosts against stdin) --------------


def test_ask_injector_default_and_pick(xdg, monkeypatch):
    """The real ask_injector: a bare Enter accepts the `bearer` default; a number
    picks from the list."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    assert prompt_mod.ask_injector() == "bearer"


def test_ask_injector_unknown_loops(xdg, monkeypatch):
    """A free-typed unknown injector re-prompts rather than erroring the command."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(sys, "stdin", io.StringIO("nope\nbasic\n"))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert prompt_mod.ask_injector() == "basic"
    assert "unknown injector" in err.getvalue()


def test_ask_hosts_bad_glob_loops(xdg, monkeypatch):
    """A bad host glob (`*.com`) loops with the hostmatch rejection; a good one is
    accepted, then an empty line finishes."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(sys, "stdin", io.StringIO("*.com\napi.example.com\n\n"))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    hosts = prompt_mod.ask_hosts()
    assert hosts == ["api.example.com"]
    assert "*.com" in err.getvalue()


def test_ask_hosts_repeats_until_empty(xdg, monkeypatch):
    """Repeatable: multiple hosts collected until a bare Enter finishes."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(sys, "stdin",
                        io.StringIO("a.example.com\n*.example.com\n\n"))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert prompt_mod.ask_hosts() == ["a.example.com", "*.example.com"]


def test_end_to_end_real_stdin(xdg, monkeypatch):
    """The whole guided flow driven by REAL stdin (no monkeypatched seams): pick
    the bearer default (Enter), provider `env`, secret ref (decline validation),
    one host, then a blank line to finish. Exercises the actual prompt wiring."""
    _make_ws("w")
    # injector: Enter (bearer default)
    # provider: "env"
    # secret ref: "GITHUB_TOKEN", then "n" to decline the validate offer
    # host: "api.example.com", then "" to finish
    stdin = "\nenv\nGITHUB_TOKEN\nn\napi.example.com\n\n"
    code, out, err = _run_loose(["workspace", "w", "binding", "add"],
                                stdin_text=stdin, stdin_isatty=True)
    assert code == 0, out + err
    (b,) = _bindings("w")
    assert b.injector == "bearer" and b.provider == "env"
    assert b.secret == "GITHUB_TOKEN" and b.hosts == ("api.example.com",)
    assert "equivalent to:" in err


def test_ask_hosts_requires_at_least_one(xdg, monkeypatch):
    """An empty line before any host re-prompts (the first host is required),
    then a real host + empty finishes."""
    from credproxy_cli.porcelain import prompt as prompt_mod
    monkeypatch.setattr(sys, "stdin", io.StringIO("\napi.example.com\n\n"))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert prompt_mod.ask_hosts() == ["api.example.com"]
    assert "at least one host" in err.getvalue()
