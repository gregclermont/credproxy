"""Tests for the usability fixes from the blind-agent round:

  - `--help` is honored on subcommands (the leaf argparse parsers are
    add_help=False, so the hand-rolled dispatch must do it) and never has a
    side effect -- in particular `scaffold --help` must not write a file named
    '--help' (the original bug).
  - `binding add`/`binding test`/`create` print descriptive help.
  - `preset list` enumerates the coordinated multi-binding sets, and a
    `--preset` add announces its expansion.
  - the scaffolded TOML template references a real injector (not the `github`
    preset) and the canonical `workspace NAME start` verb order.
"""
from __future__ import annotations

import json

import pytest

from test_porcelain import _run


# ---- scaffold --help no longer mutates state ---------------------------------


@pytest.mark.parametrize("kind", ["provider", "injector"])
def test_scaffold_help_shows_help_and_writes_nothing(kind, xdg):
    from credproxy_cli.core.paths import (
        injectors_config_dir, providers_config_dir,
    )
    code, out, err = _run([kind, "scaffold", "--help"])
    assert code == 0
    assert "scaffold NAME" in (out + err)
    # The original bug: '--help' got treated as a NAME and a file was created.
    reg = providers_config_dir() if kind == "provider" else injectors_config_dir()
    assert not reg.exists() or not any(reg.iterdir())


@pytest.mark.parametrize("kind", ["provider", "injector"])
def test_scaffold_rejects_flag_like_name(kind, xdg):
    from credproxy_cli.core.paths import (
        injectors_config_dir, providers_config_dir,
    )
    code, out, err = _run([kind, "scaffold", "--weird"])
    assert code == 1
    # Rejected, and nothing written (the real invariant).
    reg = providers_config_dir() if kind == "provider" else injectors_config_dir()
    assert not reg.exists() or not any(reg.iterdir())


def test_scaffold_core_rejects_bad_names():
    from credproxy_cli.core.scaffold import scaffold
    from credproxy_cli.core.errors import CredproxyError
    for bad in ("--help", "", "a/b", ".."):
        with pytest.raises(CredproxyError):
            scaffold("provider", bad)


# ---- uniform --help on subcommands -------------------------------------------


def test_create_help_exits_zero_with_text(xdg):
    code, out, err = _run(["workspace", "create", "--help"])
    assert code == 0
    blob = out + err
    assert "workspace create NAME" in blob and "--image" in blob


def test_binding_add_help_describes_flags(xdg):
    code, out, err = _run(["workspace", "foo", "binding", "add", "--help"])
    assert code == 0
    blob = out + err
    # The friction the blind agents hit: what does --secret mean for env?
    assert "host env var NAME" in blob
    assert "--preset" in blob and "--injector" in blob


def test_binding_test_help_exits_zero(xdg):
    code, out, err = _run(["workspace", "foo", "binding", "test", "--help"])
    assert code == 0
    assert "ad-hoc" in (out + err)


def test_dev_help_exits_zero():
    code, out, err = _run(["dev", "--help"])
    assert code == 0
    assert "build" in (out + err)


@pytest.mark.parametrize("verb", ["start", "stop", "delete", "apply",
                                  "inspect", "edit", "logs", "enter"])
def test_lifecycle_verb_help_is_descriptive(verb, xdg):
    """Each lifecycle verb's --help exits 0 with a real description (not just a
    bare `usage:` line), and -- crucially -- does NOT execute the verb."""
    code, out, err = _run(["workspace", "foo", verb, "--help"])
    assert code == 0
    blob = out + err
    assert f"workspace NAME {verb}" in blob
    assert " -- " in blob  # has a description clause, not only a usage line


def test_start_help_does_not_start(xdg):
    """--help must short-circuit before any handler runs (no docker calls)."""
    # `foo` does not exist; if start ran it would error on the missing
    # workspace/docker. Help must return cleanly instead.
    code, out, err = _run(["workspace", "foo", "start", "--help"])
    assert code == 0


# ---- preset list -------------------------------------------------------------


def test_preset_list_human():
    code, out, err = _run(["preset", "list"])
    assert code == 0
    blob = out + err
    assert "github" in blob
    assert "github-api" in blob and "github-git" in blob and "github-ghcr" in blob


def test_preset_list_json():
    code, out, err = _run(["--json", "preset", "list"])
    assert code == 0
    data = json.loads(out)
    names = {p["name"] for p in data}
    assert "github" in names
    gh = next(p for p in data if p["name"] == "github")
    assert len(gh["bindings"]) == 3
    api = next(b for b in gh["bindings"] if b["name"] == "github-api")
    assert api["injector"] == "bearer" and api["hosts"] == ["api.github.com"]


def test_preset_bare_and_help_both_list():
    for argv in (["preset"], ["preset", "--help"]):
        code, out, err = _run(argv)
        assert code == 0 and "github" in (out + err)


def test_preset_unknown_subcommand_errors():
    code, out, err = _run(["preset", "bogus"])
    assert code == 1


# ---- preset expansion is announced -------------------------------------------


def test_preset_add_announces_expansion(ws_factory):
    ws_factory("demo")
    code, out, err = _run(
        ["workspace", "demo", "binding", "add", "--preset", "github",
         "--provider", "env", "--secret", "GITHUB_TOKEN"]
    )
    assert code == 0
    assert "expands to 3 bindings" in (out + err)


# ---- preset default provider / secret ----------------------------------------


def test_preset_github_defaults_provider_and_secret(ws_factory):
    """`binding add --preset github` with no flags wires all three bindings off
    the gh-cli provider with the github.com host as the ref."""
    ws = ws_factory("demo")
    code, out, err = _run(["workspace", "demo", "binding", "add", "--preset", "github"])
    assert code == 0, out + err
    from credproxy_cli.core.bindings import load_bindings
    bindings = load_bindings(ws)
    assert {b.name for b in bindings} == {"github-api", "github-git", "github-ghcr"}
    assert all(b.provider == "gh-cli" and b.secret == "github.com" for b in bindings)


def test_preset_github_secret_override_keeps_default_provider(ws_factory):
    """An explicit --secret (e.g. an Enterprise host) overrides the ref while the
    provider still defaults to gh-cli."""
    ws = ws_factory("demo")
    code, out, err = _run(["workspace", "demo", "binding", "add",
                           "--preset", "github", "--secret", "ghe.corp.com"])
    assert code == 0, out + err
    from credproxy_cli.core.bindings import load_bindings
    assert all(b.provider == "gh-cli" and b.secret == "ghe.corp.com"
               for b in load_bindings(ws))


def test_preset_nondefault_provider_requires_secret(ws_factory):
    """A non-default provider can't borrow the default ref -- a ref's meaning is
    provider-specific -- so --secret stays required."""
    ws_factory("demo")
    code, out, err = _run(["workspace", "demo", "binding", "add",
                           "--preset", "github", "--provider", "env"])
    assert code == 1
    assert "needs --secret" in (out + err)


def test_injector_add_still_requires_provider(ws_factory):
    """With --provider now optional at the parser level (so presets can default
    it), the --injector path must still demand it explicitly."""
    ws_factory("demo")
    code, out, err = _run(["workspace", "demo", "binding", "add", "--injector",
                           "bearer", "--secret", "TOK", "--host", "api.example.com"])
    assert code == 1
    assert "needs --provider" in (out + err)


# ---- scaffolded template hygiene ---------------------------------------------


def test_template_uses_real_injector_and_verb_order(ws_factory):
    """The template must not present the `github` PRESET as an injector, and
    must use the canonical `workspace NAME start` verb order."""
    from credproxy_cli.core.config import render_template
    rendered = render_template("demo", "python:3.12-slim")
    assert 'injector = "github"' not in rendered
    assert 'injector = "bearer"' in rendered
    assert "credproxy workspace demo start" in rendered
    assert "credproxy start demo" not in rendered
