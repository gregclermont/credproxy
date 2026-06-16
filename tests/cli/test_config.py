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
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "myws", 'image = "alpine:3"\n')
    ws = Workspace("myws")
    cfg = load_config(ws)

    assert cfg["image"] == "alpine:3"
    assert cfg["home"] == "/root"          # DEFAULT_HOME fallback
    assert cfg["mounts"] == []
    assert cfg["env"] == {}
    assert cfg["setup"] == []


def test_load_config_requires_image(xdg, workspaces_dir):
    """`image` is mandatory -- there is no built-in default to fall back to;
    omitting it is a clear error (the scaffold always writes one)."""
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.errors import ConfigError
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "noimg", "")   # no image
    ws = Workspace("noimg")
    with pytest.raises(ConfigError, match="image.*required"):
        load_config(ws)


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
    with pytest.raises(ConfigError, match="image.*required.*string"):
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


_DEFAULT_IMAGE = "mcr.microsoft.com/devcontainers/base:ubuntu"


def test_render_template_is_valid_toml(xdg):
    """render_template output must be TOML-parseable, contain the name, and carry
    the literal default image (no `image` arg -- the template owns it)."""
    import tomllib
    from credproxy_cli.core.config import render_template

    text = render_template("myprojx")
    assert "myprojx" in text
    parsed = tomllib.loads(text)
    assert parsed.get("image") == _DEFAULT_IMAGE


def test_render_template_scaffolds_active_nonroot_devcontainer(xdg, workspaces_dir):
    """The literal scaffold wires the non-root vscode user, its home,
    map_host_user, and the active CA-bootstrap setup -- loads cleanly, no edits."""
    from credproxy_cli.core.config import load_config, render_template
    from credproxy_cli.core.workspace import Workspace

    (workspaces_dir / "dc.toml").write_text(render_template("dc"))
    cfg = load_config(Workspace("dc"))
    assert cfg["image"] == _DEFAULT_IMAGE
    assert cfg["user"] == "vscode"
    assert cfg["home"] == "/home/vscode"
    assert cfg["map_host_user"] is True
    assert cfg["user_uid"] == 1000
    assert cfg["setup"] == ["curl -fsSL http://proxy.local/bootstrap.sh | sh"]
    assert cfg["mounts"] == [] and cfg["env"] == {}


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
    """user/exec_flags/workdir are exec-only -> changing them must NOT change the
    spec hash (no container recreate)."""
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    withuser = {**base, "user": "dev", "exec_flags": ["--workdir", "/srv"],
                "workdir": "/code", "enter_prelude": "export X=1", "shell": ["zsh"]}
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


# ---- workdir -----------------------------------------------------------------


def test_load_config_workdir(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "w", 'image = "alpine:3"\nworkdir = "/code"\n')
    assert load_config(Workspace("w"))["workdir"] == "/code"


def test_load_config_workdir_default(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "wd", 'image = "alpine:3"\n')
    assert load_config(Workspace("wd"))["workdir"] is None


def test_load_config_workdir_not_absolute(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nworkdir = "relative"\n')
    with pytest.raises(ConfigError, match="`workdir` must be an absolute path"):
        load_config(Workspace("b"))


# ---- enter_prelude -----------------------------------------------------------


def test_load_config_enter_prelude(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "p", 'image = "alpine:3"\nenter_prelude = "export X=1"\n')
    assert load_config(Workspace("p"))["enter_prelude"] == "export X=1"


def test_load_config_enter_prelude_default_and_empty(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "pd", 'image = "alpine:3"\n')
    assert load_config(Workspace("pd"))["enter_prelude"] is None
    # explicit "" is a valid value (disables the shim)
    _write(workspaces_dir, "pe", 'image = "alpine:3"\nenter_prelude = ""\n')
    assert load_config(Workspace("pe"))["enter_prelude"] == ""


def test_load_config_enter_prelude_not_string(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nenter_prelude = 42\n')
    with pytest.raises(ConfigError, match="`enter_prelude` must be a string"):
        load_config(Workspace("b"))


# ---- shell -------------------------------------------------------------------


def test_load_config_shell(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "s", 'image = "alpine:3"\nshell = ["zsh"]\n')
    assert load_config(Workspace("s"))["shell"] == ["zsh"]


def test_load_config_shell_default_none(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "sd", 'image = "alpine:3"\n')
    assert load_config(Workspace("sd"))["shell"] is None


def test_load_config_shell_not_list(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nshell = "zsh"\n')
    with pytest.raises(ConfigError, match="`shell` must be a non-empty array"):
        load_config(Workspace("b"))


def test_load_config_shell_empty(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nshell = []\n')
    with pytest.raises(ConfigError, match="`shell` must be a non-empty array"):
        load_config(Workspace("b"))


# ---- declared_config (config --declared) -------------------------------------


def test_declared_config_raw_keys_no_defaults(xdg, workspaces_dir):
    """declared_config returns exactly what's in the file, before defaults, and
    excludes the [[binding]] array."""
    from credproxy_cli.core.config import declared_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "d", """
        image = "alpine:3"
        user = "dev"
        [[binding]]
        injector = "bearer"
        provider = "env"
        secret = "X"
        hosts = ["h"]
    """)
    assert declared_config(Workspace("d")) == {"image": "alpine:3", "user": "dev"}


def test_declared_config_missing_file(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, declared_config
    from credproxy_cli.core.workspace import Workspace

    with pytest.raises(ConfigError, match="not found"):
        declared_config(Workspace("ghost"))


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

    _write(workspaces_dir, "m", 'image = "alpine:3"\nuser = "dev"\nmap_host_user = true\n')
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


def test_spec_hash_changes_on_user_uid(xdg):
    """user_uid shapes the userns -> changing it changes the spec hash."""
    from credproxy_cli.core.config import workspace_spec_hash

    base = {"image": "x", "home": "/h", "mounts": [], "env": {}, "setup": []}
    assert workspace_spec_hash(base, "p") != workspace_spec_hash({**base, "user_uid": 1000}, "p")


def test_load_config_user_uid(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "u", 'image = "alpine:3"\nuser = "vscode"\nuser_uid = 1000\n')
    assert load_config(Workspace("u"))["user_uid"] == 1000


def test_load_config_user_uid_default_none(xdg, workspaces_dir):
    from credproxy_cli.core.config import load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "ud", 'image = "alpine:3"\n')
    assert load_config(Workspace("ud"))["user_uid"] is None


def test_load_config_user_uid_invalid(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    for bad in ('user_uid = -1', 'user_uid = "1000"', 'user_uid = true'):
        _write(workspaces_dir, "b", f'image = "alpine:3"\nuser = "dev"\n{bad}\n')
        with pytest.raises(ConfigError, match="`user_uid` must be a non-negative integer"):
            load_config(Workspace("b"))


def test_map_host_user_requires_user(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nmap_host_user = true\n')
    with pytest.raises(ConfigError, match="`map_host_user` require[s]? `user`"):
        load_config(Workspace("b"))


def test_user_uid_requires_user(xdg, workspaces_dir):
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nuser_uid = 1000\n')
    with pytest.raises(ConfigError, match="`user_uid` require[s]? `user`"):
        load_config(Workspace("b"))


def test_both_orphans_named_in_error(xdg, workspaces_dir):
    """Both offenders are named when both are set without `user`."""
    from credproxy_cli.core.config import ConfigError, load_config
    from credproxy_cli.core.workspace import Workspace

    _write(workspaces_dir, "b", 'image = "alpine:3"\nmap_host_user = true\nuser_uid = 1000\n')
    with pytest.raises(ConfigError, match="`map_host_user` and `user_uid` require `user`"):
        load_config(Workspace("b"))
