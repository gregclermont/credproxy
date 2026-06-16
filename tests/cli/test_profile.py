"""Tests for the distribution profile overlay (the org/fork customization tier).

Resolution is three tiers -- user (XDG) > profile overlay > builtin -- selected
by CREDPROXY_PROFILE_DIR. These verify that an overlay's scaffold template and
definitions (injector / preset) shadow the builtin ones.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def profile_overlay(tmp_path, monkeypatch):
    """A temp profile-overlay dir wired in via CREDPROXY_PROFILE_DIR."""
    d = tmp_path / "profile"
    d.mkdir()
    monkeypatch.setenv("CREDPROXY_PROFILE_DIR", str(d))
    return d


# ---- workspace.template.toml -------------------------------------------------


def test_overlay_template_shadows_builtin(xdg, profile_overlay):
    """An overlay's literal workspace.template.toml is used over the builtin
    (only `{name}` is substituted)."""
    (profile_overlay / "workspace.template.toml").write_text(
        '# ACME workspace {name}\nimage = "acme/base:1"\n# acme-marker\n'
    )
    from credproxy_cli.core.config import render_template
    text = render_template("w")
    assert "acme-marker" in text
    assert "ACME workspace w" in text          # {name} substituted
    assert 'image = "acme/base:1"' in text     # the overlay's literal image


# ---- definitions: injectors --------------------------------------------------


def test_overlay_injector_is_found_and_sourced(xdg, profile_overlay):
    """A new injector in the overlay resolves with source 'profile'."""
    (profile_overlay / "injectors").mkdir()
    (profile_overlay / "injectors" / "acme.toml").write_text('scheme = "bearer"\n')
    from credproxy_cli.core.injectors import find_injector, list_injectors
    inj = find_injector("acme")
    assert inj.source == "profile"
    assert "acme" in {i.name for i in list_injectors()}


def test_overlay_injector_shadows_builtin(xdg, profile_overlay):
    """A same-named overlay injector shadows the builtin one."""
    (profile_overlay / "injectors").mkdir()
    (profile_overlay / "injectors" / "bearer.toml").write_text('scheme = "basic"\n')
    from credproxy_cli.core.injectors import find_injector
    inj = find_injector("bearer")
    assert inj.source == "profile"
    assert inj.scheme == "basic"   # the overlay's, not the builtin bearer


# ---- definitions: presets ----------------------------------------------------


def test_overlay_preset_is_resolvable(xdg, profile_overlay):
    (profile_overlay / "presets").mkdir()
    (profile_overlay / "presets" / "acme.toml").write_text(
        "default_provider = \"env\"\n"
        "[placeholder]\nprefix = \"acme_\"\nlength = 32\ncharset = \"hex\"\n"
        "[[part]]\nsuffix = \"api\"\ninjector = \"bearer\"\n"
        "hosts = [\"api.acme.example\"]\nenv = \"ACME_TOKEN\"\n"
    )
    from credproxy_cli.core.presets import build_preset, load_presets
    assert "acme" in load_presets()
    assert "github" in load_presets()   # builtin still present
    bindings = build_preset("acme", "env", "ACME_TOKEN")
    assert [b.name for b in bindings] == ["acme-api"]
    assert bindings[0].hosts == ("api.acme.example",)
