"""Tests for core/bindings.py: parse/validate, auto-name generation,
materialization, append/remove surgical edits, and wire_config shape."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


# ---- helpers -----------------------------------------------------------------


def _write_ws(workspaces_dir: Path, name: str, content: str):
    """Write a workspace TOML and return a Workspace."""
    from credproxy_cli.core.workspace import Workspace
    p = workspaces_dir / f"{name}.toml"
    p.write_text(textwrap.dedent(content))
    return Workspace(name)


# ---- auto-name generation ----------------------------------------------------


def test_auto_name_no_collision():
    from credproxy_cli.core.bindings import _auto_name

    assert _auto_name("github", "env", set()) == "github-env"


def test_auto_name_first_collision():
    from credproxy_cli.core.bindings import _auto_name

    taken = {"github-env"}
    assert _auto_name("github", "env", taken) == "github-env-2"


def test_auto_name_multi_collision():
    from credproxy_cli.core.bindings import _auto_name

    taken = {"github-env", "github-env-2", "github-env-3"}
    assert _auto_name("github", "env", taken) == "github-env-4"


def test_auto_name_no_prefix_suffix_cross_collision():
    """github-env-2 existing should not prevent github-env from being used."""
    from credproxy_cli.core.bindings import _auto_name

    taken = {"github-env-2"}
    assert _auto_name("github", "env", taken) == "github-env"


# ---- parse / validate --------------------------------------------------------


def test_parse_missing_injector(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{"provider": "env", "secret": "X", "hosts": ["h.io"]}]}
    with pytest.raises(ConfigError, match="injector is required"):
        _parse_bindings(raw, "test")


def test_parse_missing_provider(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{"injector": "github", "secret": "X", "hosts": ["h.io"]}]}
    with pytest.raises(ConfigError, match="provider is required"):
        _parse_bindings(raw, "test")


def test_parse_missing_secret(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{"injector": "github", "provider": "env", "hosts": ["h.io"]}]}
    with pytest.raises(ConfigError, match="secret is required"):
        _parse_bindings(raw, "test")


def test_parse_empty_hosts(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{"injector": "github", "provider": "env", "secret": "X", "hosts": []}]}
    with pytest.raises(ConfigError, match="hosts is required"):
        _parse_bindings(raw, "test")


def test_parse_hosts_not_array(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{"injector": "github", "provider": "env", "secret": "X", "hosts": "api.github.com"}]}
    with pytest.raises(ConfigError, match="hosts is required"):
        _parse_bindings(raw, "test")


def test_parse_empty_name_rejected(xdg):
    from credproxy_cli.core.bindings import _parse_bindings
    from credproxy_cli.core.errors import ConfigError

    raw = {"binding": [{
        "injector": "github", "provider": "env", "secret": "X",
        "hosts": ["h.io"], "name": ""
    }]}
    with pytest.raises(ConfigError, match="name must be a non-empty string"):
        _parse_bindings(raw, "test")


def test_validate_duplicate_name(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import Binding, validate
    from credproxy_cli.core.errors import ConfigError

    b = Binding(name="dup", injector="github", provider="env",
                secret="X", hosts=("api.github.com",), placeholder="p", env=None)
    with pytest.raises(ConfigError, match="duplicate binding name"):
        validate([b, b], "test")


def test_validate_duplicate_host_header(xdg, workspaces_dir):
    """Two bindings with the same injector (header) and same host should fail."""
    from credproxy_cli.core.bindings import Binding, validate
    from credproxy_cli.core.errors import ConfigError

    b1 = Binding(name="b1", injector="github", provider="env",
                 secret="X", hosts=("api.github.com",), placeholder="p1", env=None)
    b2 = Binding(name="b2", injector="github", provider="env",
                 secret="Y", hosts=("api.github.com",), placeholder="p2", env=None)
    with pytest.raises(ConfigError, match="both claim header"):
        validate([b1, b2], "test")


def test_validate_unknown_injector(xdg, workspaces_dir):
    """validate() raises InjectorError if injector name is not found."""
    from credproxy_cli.core.bindings import Binding, validate
    from credproxy_cli.core.errors import InjectorError

    b = Binding(name="b", injector="nonexistent_zzz", provider="env",
                secret="X", hosts=("h.io",), placeholder="p", env=None)
    with pytest.raises(InjectorError):
        validate([b], "test")


def test_validate_unknown_provider(xdg, workspaces_dir):
    """validate() raises ProviderError if provider name is not found."""
    from credproxy_cli.core.bindings import Binding, validate
    from credproxy_cli.core.errors import ProviderError

    b = Binding(name="b", injector="github", provider="nonexistent_zzz",
                secret="X", hosts=("api.github.com",), placeholder="p", env=None)
    with pytest.raises(ProviderError):
        validate([b], "test")


# ---- materialization ---------------------------------------------------------


def test_materialize_writes_name_and_placeholder(xdg, workspaces_dir):
    """A binding without name/placeholder gets both materialized on disk."""
    ws = _write_ws(workspaces_dir, "mat", """\
        image = "x"

        [[binding]]
        injector = "github"
        provider = "env"
        secret   = "GITHUB_TOKEN"
        hosts    = ["api.github.com"]
    """)
    from credproxy_cli.core.bindings import materialize_bindings
    import tomllib

    notified = []
    bindings = materialize_bindings(ws, notify=notified.append)

    assert len(bindings) == 1
    b = bindings[0]
    assert b.name == "github-env"
    assert b.placeholder is not None
    assert b.placeholder.startswith("ghp_")
    assert len(b.placeholder) == 40

    # File must be updated
    raw = tomllib.loads(ws.config_path.read_text())
    on_disk = raw["binding"][0]
    assert on_disk["name"] == "github-env"
    assert on_disk["placeholder"] == b.placeholder

    # Two notifications
    assert any("name" in msg for msg in notified)
    assert any("placeholder" in msg for msg in notified)


def test_materialize_idempotent(xdg, workspaces_dir):
    """Running materialize_bindings twice must leave the file unchanged."""
    ws = _write_ws(workspaces_dir, "idem", """\
        image = "x"

        [[binding]]
        injector = "github"
        provider = "env"
        secret   = "GITHUB_TOKEN"
        hosts    = ["api.github.com"]
    """)
    from credproxy_cli.core.bindings import materialize_bindings

    # First pass: materializes
    bs1 = materialize_bindings(ws)
    text_after_first = ws.config_path.read_text()

    # Second pass: must NOT change the file
    bs2 = materialize_bindings(ws)
    text_after_second = ws.config_path.read_text()

    assert text_after_first == text_after_second
    assert bs1[0].placeholder == bs2[0].placeholder


def test_materialize_preserves_comments(xdg, workspaces_dir):
    """Comments in the binding block survive materialization."""
    ws = _write_ws(workspaces_dir, "cmt", """\
        image = "x"

        # outer comment
        [[binding]]
        # inner comment
        injector = "github"
        provider = "env"
        secret   = "GITHUB_TOKEN"
        hosts    = ["api.github.com"]
    """)
    from credproxy_cli.core.bindings import materialize_bindings

    materialize_bindings(ws)
    text = ws.config_path.read_text()
    assert "# outer comment" in text
    assert "# inner comment" in text


def test_materialize_auto_name_collision(xdg, workspaces_dir):
    """Two unnamed bindings with the same injector/provider get distinct names."""
    ws = _write_ws(workspaces_dir, "coll", """\
        image = "x"

        [[binding]]
        injector = "github"
        provider = "env"
        secret   = "TOK1"
        hosts    = ["api.github.com"]

        [[binding]]
        injector = "github"
        provider = "env"
        secret   = "TOK2"
        hosts    = ["uploads.github.com"]
    """)
    from credproxy_cli.core.bindings import materialize_bindings

    bindings = materialize_bindings(ws)
    names = [b.name for b in bindings]
    assert len(set(names)) == 2  # both distinct
    assert "github-env" in names
    assert "github-env-2" in names


def test_materialize_placeholder_already_set(xdg, workspaces_dir):
    """A binding that already has a placeholder keeps it unchanged."""
    ws = _write_ws(workspaces_dir, "existing_ph", """\
        image = "x"

        [[binding]]
        injector    = "github"
        provider    = "env"
        secret      = "GITHUB_TOKEN"
        hosts       = ["api.github.com"]
        name        = "mygh"
        placeholder = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    """)
    from credproxy_cli.core.bindings import materialize_bindings

    bs = materialize_bindings(ws)
    assert bs[0].placeholder == "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


# ---- append_binding / remove_binding ----------------------------------------


def test_append_binding_round_trip(xdg, workspaces_dir):
    """append_binding writes a valid block; remove_binding removes it."""
    ws = _write_ws(workspaces_dir, "ar", 'image = "x"\n')
    from credproxy_cli.core.bindings import Binding, append_binding, remove_binding
    import tomllib

    b = Binding(
        name="mygh", injector="github", provider="env",
        secret="TOK", hosts=("api.github.com",), placeholder="ghp_xxx", env="GITHUB_TOKEN",
    )
    append_binding(ws, b)

    raw = tomllib.loads(ws.config_path.read_text())
    assert len(raw.get("binding", [])) == 1
    on_disk = raw["binding"][0]
    assert on_disk["name"] == "mygh"
    assert on_disk["placeholder"] == "ghp_xxx"
    assert on_disk["env"] == "GITHUB_TOKEN"

    remove_binding(ws, "mygh")
    raw2 = tomllib.loads(ws.config_path.read_text())
    assert len(raw2.get("binding", [])) == 0


def test_remove_binding_not_found(xdg, workspaces_dir):
    ws = _write_ws(workspaces_dir, "rm_ghost", 'image = "x"\n')
    from credproxy_cli.core.bindings import remove_binding
    from credproxy_cli.core.errors import ConfigError

    with pytest.raises(ConfigError, match="not found"):
        remove_binding(ws, "nosuchbinding")


def test_append_multiple_then_remove_middle(xdg, workspaces_dir):
    """Removing the second of three bindings leaves the other two intact."""
    ws = _write_ws(workspaces_dir, "mid", 'image = "x"\n')
    from credproxy_cli.core.bindings import Binding, append_binding, remove_binding
    import tomllib

    def make(name, host):
        return Binding(name=name, injector="github", provider="env",
                       secret="X", hosts=(host,), placeholder="phx", env=None)

    append_binding(ws, make("first", "a.io"))
    append_binding(ws, make("second", "b.io"))
    append_binding(ws, make("third", "c.io"))

    remove_binding(ws, "second")
    raw = tomllib.loads(ws.config_path.read_text())
    names = [b["name"] for b in raw.get("binding", [])]
    assert names == ["first", "third"]


# ---- wire_config shape -------------------------------------------------------


def test_wire_config_shape(xdg, workspaces_dir):
    """wire_config produces exact expected JSON shape (with stub fetch)."""
    from credproxy_cli.core.bindings import Binding, wire_config

    b = Binding(
        name="gh", injector="github", provider="env",
        secret="GITHUB_TOKEN", hosts=("api.github.com",),
        placeholder="ghp_test_placeholder_val123456789012",
        env="GITHUB_TOKEN",
    )

    def fake_fetch(provider, secret):
        return "real_secret_value"

    result = wire_config([b], fetch=fake_fetch)

    assert "bindings" in result
    assert len(result["bindings"]) == 1
    entry = result["bindings"][0]
    assert entry["name"] == "gh"
    assert entry["hosts"] == ["api.github.com"]
    assert entry["header"] == "Authorization"
    assert entry["placeholder"] == "ghp_test_placeholder_val123456789012"
    assert entry["real"] == "real_secret_value"
    assert entry["env"] == "GITHUB_TOKEN"


def test_wire_config_no_env_field_when_absent(xdg, workspaces_dir):
    """wire_config omits `env` key when neither binding nor injector has one."""
    from credproxy_cli.core.bindings import Binding, wire_config

    # bearer injector has no env
    b = Binding(
        name="plain", injector="bearer", provider="env",
        secret="TOK", hosts=("example.com",),
        placeholder="credproxy_testplacholder12345678901",
        env=None,
    )

    result = wire_config([b], fetch=lambda p, s: "val")
    entry = result["bindings"][0]
    assert "env" not in entry


def test_wire_config_binding_env_overrides_injector(xdg, workspaces_dir):
    """Binding-level env overrides the injector's suggested env."""
    from credproxy_cli.core.bindings import Binding, wire_config

    b = Binding(
        name="gh", injector="github", provider="env",
        secret="X", hosts=("api.github.com",),
        placeholder="ghp_test_placeholder_val123456789012",
        env="MY_CUSTOM_TOKEN",  # overrides injector's GITHUB_TOKEN
    )

    result = wire_config([b], fetch=lambda p, s: "v")
    assert result["bindings"][0]["env"] == "MY_CUSTOM_TOKEN"


def test_wire_config_missing_placeholder_raises(xdg):
    from credproxy_cli.core.bindings import Binding, wire_config
    from credproxy_cli.core.errors import ConfigError

    b = Binding(
        name="noph", injector="github", provider="env",
        secret="X", hosts=("h.io",), placeholder=None, env=None,
    )
    with pytest.raises(ConfigError, match="no placeholder"):
        wire_config([b], fetch=lambda p, s: "v")
