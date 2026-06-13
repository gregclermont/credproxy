"""Tests for core/injectors.py: scheme-based schema validation, placeholder
generation, user-dir shadowing bundled."""
from __future__ import annotations

import pytest


# ---- bundled injectors -------------------------------------------------------


def test_find_bundled_bearer(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("bearer")
    assert inj.name == "bearer"
    assert inj.scheme == "bearer"
    assert inj.params == {"header": "Authorization"}  # default merged in
    assert inj.env is None
    assert inj.source == "bundled"


def test_find_bundled_basic(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("basic")
    assert inj.scheme == "basic"
    assert inj.params == {"header": "Authorization"}
    assert inj.source == "bundled"


def test_find_bundled_body(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("body")
    assert inj.scheme == "body"
    assert inj.params == {}
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
    (user_dir / "bearer.toml").write_text(
        'scheme = "bearer"\n[params]\nheader = "X-Custom-Auth"\n'
    )

    from credproxy_cli.core.injectors import find_injector
    inj = find_injector("bearer")
    assert inj.params["header"] == "X-Custom-Auth"
    assert inj.source == "user"


# ---- schema validation -------------------------------------------------------


def test_injector_missing_scheme(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badone.toml").write_text('env = "X"\n')

    with pytest.raises(InjectorError, match="`scheme` is required"):
        find_injector("badone")


def test_injector_unknown_scheme(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badscheme.toml").write_text('scheme = "telepathy"\n')

    with pytest.raises(InjectorError, match="unknown scheme"):
        find_injector("badscheme")


def test_injector_params_not_table(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badparams.toml").write_text('scheme = "bearer"\nparams = "nope"\n')

    with pytest.raises(InjectorError, match="\\[params\\] must be a table"):
        find_injector("badparams")


def test_injector_placeholder_unknown_charset(xdg):
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.paths import injectors_config_dir

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "badcs.toml").write_text(
        'scheme = "bearer"\n'
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
        'scheme = "bearer"\n'
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
    assert len(values) > 1


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
    assert "bearer" in names
    assert "basic" in names
    assert "body" in names


def test_list_injectors_user_shadows(xdg):
    from credproxy_cli.core.paths import injectors_config_dir
    from credproxy_cli.core.injectors import list_injectors

    user_dir = injectors_config_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "bearer.toml").write_text('scheme = "bearer"\n[params]\nheader = "X-User"\n')

    injectors = {i.name: i for i in list_injectors()}
    assert injectors["bearer"].source == "user"
    assert injectors["basic"].source == "bundled"
