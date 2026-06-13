"""Tests for core/injectors.py: schema validation, placeholder generation,
user-dir shadowing bundled."""
from __future__ import annotations

import pytest


# ---- bundled injectors -------------------------------------------------------


def test_find_bundled_github(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("github")
    assert inj.name == "github"
    assert inj.header == "Authorization"
    assert inj.format == "Bearer {value}"
    assert inj.env == "GITHUB_TOKEN"
    assert inj.placeholder.prefix == "ghp_"
    assert inj.placeholder.length == 40
    assert inj.placeholder.charset == "alnumeric"
    assert inj.source == "bundled"


def test_find_bundled_bearer(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("bearer")
    assert inj.name == "bearer"
    assert inj.header == "Authorization"
    assert inj.env is None
    assert inj.source == "bundled"


def test_find_injector_not_found(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="not found"):
        find_injector("totally_nonexistent_zzz")


# ---- user injector shadows bundled -------------------------------------------


def test_user_injector_shadows_bundled(xdg, tmp_path, monkeypatch):
    """A user injector with the same name takes precedence over bundled."""
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    # Override github with a custom header
    (user_dir / "github.toml").write_text(
        'header = "X-Custom-Auth"\nformat = "{value}"\n'
    )

    from credproxy_cli.core.injectors import find_injector
    inj = find_injector("github")
    assert inj.header == "X-Custom-Auth"
    assert inj.source == "user"


# ---- schema validation -------------------------------------------------------


def test_injector_missing_header(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badone.toml").write_text('format = "{value}"\n')

    with pytest.raises(InjectorError, match="`header` is required"):
        find_injector("badone")


def test_injector_format_missing_value_placeholder(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badfmt.toml").write_text('header = "Auth"\nformat = "no_placeholder_token"\n')

    with pytest.raises(InjectorError, match="format"):
        find_injector("badfmt")


def test_injector_placeholder_unknown_charset(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badcs.toml").write_text(
        'header = "Auth"\nformat = "{value}"\n'
        '[placeholder]\nprefix = "x_"\nlength = 20\ncharset = "emoji"\n'
    )

    with pytest.raises(InjectorError, match="charset"):
        find_injector("badcs")


def test_injector_placeholder_length_too_short(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "shorty.toml").write_text(
        'header = "Auth"\nformat = "{value}"\n'
        '[placeholder]\nprefix = "toolongprefix_"\nlength = 5\n'
    )

    with pytest.raises(InjectorError, match="length"):
        find_injector("shorty")


# ---- placeholder generation --------------------------------------------------


def test_placeholder_generate_length_and_prefix():
    from credproxy_cli.core.injectors import Placeholder

    ph = Placeholder(prefix="ghp_", length=40, charset="alnumeric")
    value = ph.generate()
    assert value.startswith("ghp_")
    assert len(value) == 40


def test_placeholder_generate_uses_correct_charset_hex():
    from credproxy_cli.core.injectors import Placeholder

    ph = Placeholder(prefix="", length=32, charset="hex")
    value = ph.generate()
    assert all(c in "0123456789abcdef" for c in value)
    assert len(value) == 32


def test_placeholder_generate_randomness():
    """Two generated placeholders should (almost certainly) differ."""
    from credproxy_cli.core.injectors import Placeholder

    ph = Placeholder(prefix="credproxy_", length=40, charset="alnumeric")
    values = {ph.generate() for _ in range(10)}
    assert len(values) > 1  # extremely unlikely to fail


def test_placeholder_generate_base64url_charset():
    from credproxy_cli.core.injectors import Placeholder
    import string

    ph = Placeholder(prefix="t_", length=20, charset="base64url")
    value = ph.generate()
    alphabet = set(string.ascii_letters + string.digits + "-_")
    assert all(c in alphabet for c in value[2:])


# ---- list_injectors ----------------------------------------------------------


def test_list_injectors_includes_bundled(xdg):
    from credproxy_cli.core.injectors import list_injectors

    names = [i.name for i in list_injectors()]
    assert "github" in names
    assert "bearer" in names


def test_list_injectors_user_shadows(xdg):
    from credproxy_cli.core.paths import injectors_config_dir
    from credproxy_cli.core.injectors import list_injectors

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "github.toml").write_text('header = "X-User"\nformat = "{value}"\n')

    injectors = {i.name: i for i in list_injectors()}
    assert injectors["github"].source == "user"
    # bundled bearer still present
    assert injectors["bearer"].source == "bundled"
