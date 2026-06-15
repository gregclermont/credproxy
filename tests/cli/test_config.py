"""Tests for core/config.py: load_config validation rules, template round-trip,
and workspace_spec_hash."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


# ---- helpers -----------------------------------------------------------------


def _write(workspaces_dir: Path, name: str, content: str):
    p = workspaces_dir / f"{name}.toml"
    p.write_text(textwrap.dedent(content))
    return p


# ---- happy path / defaults ---------------------------------------------------


def test_load_config_minimal(xdg, workspaces_dir):
    """Minimal config (image only) loads and applies defaults."""
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.paths import DEFAULT_HOME, DEFAULT_WORKSPACE_IMAGE
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "myws", 'image = "alpine:3"\n')
    ws = Workspace("myws")
    cfg = load_config(ws)

    assert cfg["image"] == "alpine:3"
    assert cfg["home"] == DEFAULT_HOME
    assert cfg["mounts"] == []
    assert cfg["env"] == {}
    assert cfg["setup"] == []


def test_load_config_default_image(xdg, workspaces_dir):
    """Empty image string falls back to the default."""
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.paths import DEFAULT_WORKSPACE_IMAGE
    from credproxy_cli.core.workspace import Workspace

    # omitted image entirely
    _write(workspaces_dir, "noimg", "")
    ws = Workspace("noimg")
    cfg = load_config(ws)
    assert cfg["image"] == DEFAULT_WORKSPACE_IMAGE


def test_load_config_full(xdg, tmp_path, workspaces_dir):
    """Config with all fields present is loaded correctly."""
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    # We need an existing directory for the mount source.
    src = tmp_path / "code"
    src.mkdir()

    _write(workspaces_dir, "full", f"""\
        image = "ubuntu:22.04"
        home = "/home/user"
        mounts = ["{src}:/code"]
        env = {{ FOO = "bar" }}
        setup = ["echo hi"]
    """)
    ws = Workspace("full")
    cfg = load_config(ws)

    assert cfg["image"] == "ubuntu:22.04"
    assert cfg["home"] == "/home/user"
    assert len(cfg["mounts"]) == 1
    assert cfg["mounts"][0]["source"] == str(src)
    assert cfg["mounts"][0]["target"] == "/code"
    assert cfg["mounts"][0]["readonly"] is False
    assert cfg["env"] == {"FOO": "bar"}
    assert cfg["setup"] == ["echo hi"]


def test_load_config_mount_readonly(xdg, tmp_path, workspaces_dir):
    """Mount with `:ro` suffix is parsed as readonly."""
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    src = tmp_path / "ro"
    src.mkdir()
    _write(workspaces_dir, "rome", f'image = "x"\nmounts = ["{src}:/data:ro"]\n')
    ws = Workspace("rome")
    cfg = load_config(ws)
    assert cfg["mounts"][0]["readonly"] is True


# ---- validation errors -------------------------------------------------------


def test_load_config_missing_file(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    ws = Workspace("ghost")
    with pytest.raises(ConfigError, match="not found"):
        load_config(ws)


def test_load_config_bad_toml(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", "image = [unterminated")
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="TOML parse error"):
        load_config(ws)


def test_load_config_image_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", "image = 42\n")
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`image` must be a string"):
        load_config(ws)


def test_load_config_home_not_absolute(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nhome = "relative/path"\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`home` must be an absolute path"):
        load_config(ws)


def test_load_config_home_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nhome = 99\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`home` must be an absolute path"):
        load_config(ws)


def test_load_config_mounts_not_array(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nmounts = "notarray"\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`mounts` must be an array"):
        load_config(ws)


def test_load_config_mount_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nmounts = [42]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match='mounts\\[0\\] must be a string'):
        load_config(ws)


def test_load_config_mount_bad_format(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nmounts = ["/only"]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match='expected "SRC:DST"'):
        load_config(ws)


def test_load_config_mount_source_not_absolute(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nmounts = ["relative:/dst"]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="source must be absolute"):
        load_config(ws)


def test_load_config_mount_source_missing(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nmounts = ["/nonexistent_zz:/dst"]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(ws)


def test_load_config_mount_target_not_absolute(xdg, tmp_path, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    src = tmp_path / "s"
    src.mkdir()
    _write(workspaces_dir, "bad", f'image = "x"\nmounts = ["{src}:relative"]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="target must be absolute"):
        load_config(ws)


def test_load_config_env_not_dict(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nenv = "notatable"\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`env` must be a table"):
        load_config(ws)


def test_load_config_env_value_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\n[env]\nFOO = 42\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="must be a string"):
        load_config(ws)


def test_load_config_setup_not_array(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nsetup = "single string"\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="`setup` must be an array"):
        load_config(ws)


def test_load_config_setup_item_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "bad", 'image = "x"\nsetup = [42]\n')
    ws = Workspace("bad")
    with pytest.raises(ConfigError, match="setup\\[0\\] must be a string"):
        load_config(ws)


# ---- template scaffold round-trip -------------------------------------------


def test_render_template_is_valid_toml(xdg):
    """render_template output must be TOML-parseable and contain the name."""
    import tomllib
    from credproxy_cli.core.config import render_template

    text = render_template("myprojx", "python:3.12-slim")
    assert "myprojx" in text
    parsed = tomllib.loads(text)
    assert parsed.get("image") == "python:3.12-slim"


def test_render_template_defaults_apply(xdg, workspaces_dir):
    """A scaffolded template with no edits loads cleanly via load_config."""
    from credproxy_cli.core.config import load_config, render_template
    from credproxy_cli.core.paths import DEFAULT_WORKSPACE_IMAGE
    from credproxy_cli.core.workspace import Workspace

    text = render_template("scaffold_ws", DEFAULT_WORKSPACE_IMAGE)
    (workspaces_dir / "scaffold_ws.toml").write_text(text)
    ws = Workspace("scaffold_ws")
    cfg = load_config(ws)
    assert cfg["image"] == DEFAULT_WORKSPACE_IMAGE
    assert cfg["mounts"] == []
    assert cfg["env"] == {}
    assert cfg["setup"] == []


# ---- spec hash ---------------------------------------------------------------


def test_spec_hash_stable(xdg):
    """Same inputs yield the same hash."""
    from credproxy_cli.core.config import workspace_spec_hash

    cfg = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    h1 = workspace_spec_hash(cfg, "abc")
    h2 = workspace_spec_hash(cfg, "abc")
    assert h1 == h2
    assert len(h1) == 16


def test_spec_hash_changes_on_image(xdg):
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    import copy
    alt = copy.deepcopy(base)
    alt["image"] = "y"
    assert workspace_spec_hash(base, None) != workspace_spec_hash(alt, None)


def test_spec_hash_changes_on_proxy_id(xdg):
    from credproxy_cli.core.config import workspace_spec_hash

    cfg = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    assert workspace_spec_hash(cfg, "a") != workspace_spec_hash(cfg, "b")


def test_spec_hash_ignores_user_and_exec_flags(xdg):
    """user/exec_flags are exec-only -> changing them must NOT change the spec
    hash (no container recreate)."""
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    withuser = {**base, "user": "dev", "exec_flags": ["--workdir", "/srv"]}
    assert workspace_spec_hash(base, "p") == workspace_spec_hash(withuser, "p")


def test_spec_hash_changes_on_run_flags(xdg):
    """run_flags shape the container -> changing them MUST change the spec hash
    (forces a recreate). A missing run_flags hashes the same as []."""
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    assert workspace_spec_hash(base, "p") == workspace_spec_hash({**base, "run_flags": []}, "p")
    withflags = {**base, "run_flags": ["--userns=keep-id:uid=1000,gid=1000"]}
    assert workspace_spec_hash(base, "p") != workspace_spec_hash(withflags, "p")


# ---- user / exec_flags -------------------------------------------------------


def test_load_config_user_and_exec_flags(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "u", """
        image = "alpine:3"
        user = "dev"
        exec_flags = ["--workdir", "/srv"]
    """)
    cfg = load_config(Workspace("u"))
    assert cfg["user"] == "dev"
    assert cfg["exec_flags"] == ["--workdir", "/srv"]


def test_load_config_user_exec_flags_default(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "d", 'image = "alpine:3"\n')
    cfg = load_config(Workspace("d"))
    assert cfg["user"] is None
    assert cfg["exec_flags"] == []


def test_load_config_user_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nuser = 5\n')
    with pytest.raises(ConfigError, match="`user` must be a non-empty string"):
        load_config(Workspace("b"))


def test_load_config_exec_flags_not_list_of_strings(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nexec_flags = [1, 2]\n')
    with pytest.raises(ConfigError, match="`exec_flags` must be an array of strings"):
        load_config(Workspace("b"))


# ---- run_flags ---------------------------------------------------------------


def test_load_config_run_flags(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "r", """
        image = "alpine:3"
        run_flags = ["--userns=keep-id:uid=1000,gid=1000"]
    """)
    cfg = load_config(Workspace("r"))
    assert cfg["run_flags"] == ["--userns=keep-id:uid=1000,gid=1000"]


def test_load_config_run_flags_default(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "rd", 'image = "alpine:3"\n')
    assert load_config(Workspace("rd"))["run_flags"] == []


def test_load_config_run_flags_not_list_of_strings(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nrun_flags = [1, 2]\n')
    with pytest.raises(ConfigError, match="`run_flags` must be an array of strings"):
        load_config(Workspace("b"))


# ---- map_host_user -----------------------------------------------------------


def test_load_config_map_host_user(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "m", 'image = "alpine:3"\nmap_host_user = true\n')
    assert load_config(Workspace("m"))["map_host_user"] is True


def test_load_config_map_host_user_default(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "md", 'image = "alpine:3"\n')
    assert load_config(Workspace("md"))["map_host_user"] is False


def test_load_config_map_host_user_not_bool(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nmap_host_user = "yes"\n')
    with pytest.raises(ConfigError, match="`map_host_user` must be a boolean"):
        load_config(Workspace("b"))


def test_spec_hash_changes_on_map_host_user(xdg):
    """map_host_user shapes the container -> changing it changes the spec hash."""
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    assert workspace_spec_hash(base, "p") == workspace_spec_hash({**base, "map_host_user": False}, "p")
    assert workspace_spec_hash(base, "p") != workspace_spec_hash({**base, "map_host_user": True}, "p")
