"""Tests for the `user` + `exec_flags` enter knobs (#8): the docker-exec argv
assembly (_enter_exec_cmd) and the `enter --user` override flag parsing.

The argv ordering is load-bearing: credproxy's session-control flags come LAST as
explicit booleans so a stray -d/-t/-i in exec_flags can't detach the session or
break pidfile/auto-stop tracking (docker is last-wins).
"""
from __future__ import annotations


def _cmd(cfg, *, user_override=None, isatty=True, cmd=None):
    from credproxy_cli.core.lifecycle import _enter_exec_cmd
    return _enter_exec_cmd(cfg, "ctr", cmd or ["bash"],
                           user_override=user_override, isatty=isatty)


def test_plain_no_user_no_flags():
    out = _cmd({})
    # session-control prefix + container, then the env-shim-wrapped command.
    assert out[:6] == ["docker", "exec", "--interactive=true", "--tty=true",
                       "--detach=false", "ctr"]
    assert out[6:8] == ["sh", "-c"]
    assert out[-2:] == ["credproxy-enter", "bash"]


def test_config_user():
    out = _cmd({"user": "dev"})
    # -u dev comes before the session-control flags and the container.
    assert out[:4] == ["docker", "exec", "-u", "dev"]
    assert out[-1] == "bash"        # the (shim-wrapped) command
    assert "ctr" in out


# ---- enter env shim ----------------------------------------------------------


def test_enter_wraps_command_in_env_shim_by_default():
    out = _cmd({}, cmd=["npm", "test"])
    i = out.index("ctr")
    assert out[i + 1:i + 3] == ["sh", "-c"]
    script = out[i + 3]
    assert script.endswith('exec "$@"')
    assert "credproxy.sh" in script              # default sources the CA-env file
    assert out[i + 4] == "credproxy-enter"       # $0 label
    assert out[i + 5:] == ["npm", "test"]        # command preserved as "$@"


def test_enter_prelude_override():
    out = _cmd({"enter_prelude": "export X=1"}, cmd=["bash"])
    assert out[out.index("-c") + 1] == 'export X=1; exec "$@"'


def test_enter_prelude_empty_disables_shim():
    out = _cmd({"enter_prelude": ""}, cmd=["npm", "test"])
    # no wrapper -- command execs directly after the container
    assert "sh" not in out[out.index("ctr"):]
    assert out[-3:] == ["ctr", "npm", "test"]


def test_exec_flags_spliced_before_session_control():
    out = _cmd({"exec_flags": ["--workdir", "/srv"]})
    assert "--workdir" in out and "/srv" in out
    # exec_flags precede credproxy's session-control flags (which win last).
    assert out.index("--workdir") < out.index("--detach=false")


def test_workdir_defaults_to_home():
    """With no `workdir`, enter lands in `home` (not the image's WORKDIR)."""
    out = _cmd({"home": "/home/vscode"})
    assert out[out.index("--workdir") + 1] == "/home/vscode"
    # before the session-control flags and the container
    assert out.index("--workdir") < out.index("--detach=false")


def test_workdir_field_overrides_home():
    out = _cmd({"home": "/home/vscode", "workdir": "/code"})
    assert out[out.index("--workdir") + 1] == "/code"
    assert "/home/vscode" not in out


def test_exec_flags_workdir_wins_over_default():
    """credproxy's default --workdir precedes exec_flags, so a --workdir there
    overrides it (docker last-wins)."""
    out = _cmd({"home": "/home/vscode", "exec_flags": ["--workdir", "/srv"]})
    positions = [i for i, a in enumerate(out) if a == "--workdir"]
    assert len(positions) == 2                       # default + exec_flags
    assert out[positions[0] + 1] == "/home/vscode"   # credproxy default, first
    assert out[positions[-1] + 1] == "/srv"          # exec_flags, last -> wins


def test_no_workdir_without_home_or_workdir():
    """No home and no workdir -> no --workdir injected (unit-level cfg)."""
    assert "--workdir" not in _cmd({})


def test_user_override_beats_config_user():
    out = _cmd({"user": "dev"}, user_override="root")
    # config user is suppressed; the override is the only -u.
    assert out.count("-u") == 1
    assert out[out.index("-u") + 1] == "root"


def test_session_control_neutralizes_stray_detach():
    """A -d in exec_flags is overridden by the trailing --detach=false."""
    out = _cmd({"exec_flags": ["-d"]})
    assert out.index("-d") < out.index("--detach=false")  # last wins -> not detached


def test_tty_false_when_not_a_terminal():
    assert "--tty=false" in _cmd({}, isatty=False)
    assert "--tty=true" not in _cmd({}, isatty=False)


def test_enter_parser_accepts_user_flag():
    from credproxy_cli.porcelain.cli import _build_leaf_parser
    a = _build_leaf_parser().parse_args(["enter", "--user", "root"])
    assert a.verb == "enter" and a.enter_user == "root"


def test_enter_parser_user_defaults_none():
    from credproxy_cli.porcelain.cli import _build_leaf_parser
    a = _build_leaf_parser().parse_args(["enter"])
    assert a.enter_user is None
