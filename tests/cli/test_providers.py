"""Tests for core/providers.py: registry lookup, protocol invocation against
real test provider scripts, bundled env provider, and error paths."""
from __future__ import annotations

import json
import os
import stat
import textwrap
from pathlib import Path

import pytest


# ---- helpers -----------------------------------------------------------------


def _make_provider(providers_dir: Path, name: str, script: str) -> Path:
    """Write an executable provider script to providers_dir/<name>."""
    p = providers_dir / name
    p.write_text(textwrap.dedent(script))
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _make_dir_provider(providers_dir: Path, name: str, script: str) -> Path:
    """Write a dir-based provider: providers_dir/<name>/run."""
    d = providers_dir / name
    d.mkdir()
    p = d / "run"
    p.write_text(textwrap.dedent(script))
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


# ---- find_provider / registry ------------------------------------------------


def test_find_bundled_env(xdg):
    from credproxy_cli.core.providers import find_provider

    p = find_provider("env")
    assert p.name == "env"
    assert p.source == "bundled"
    assert p.exe.is_file()
    assert os.access(p.exe, os.X_OK)


def test_find_provider_not_found(xdg):
    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import find_provider

    with pytest.raises(ProviderError, match="not found"):
        find_provider("nonexistent_zzz_provider")


def test_find_provider_file_not_executable(xdg):
    """A non-executable file raises a helpful ProviderError."""
    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import find_provider
    from credproxy_cli.core.paths import providers_config_dir

    d = providers_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / "notexec"
    p.write_text("not a script")
    p.chmod(0o644)  # no execute bit

    with pytest.raises(ProviderError, match="not an executable"):
        find_provider("notexec")


def test_find_provider_user_shadows_bundled(xdg):
    """A user provider with the same name as a bundled one takes precedence."""
    from credproxy_cli.core.paths import providers_config_dir
    from credproxy_cli.core.providers import find_provider

    d = providers_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    _make_provider(d, "env", "#!/bin/sh\necho '{\"value\":\"user\"}'\n")

    p = find_provider("env")
    assert p.source == "user"


def test_find_provider_dir_with_run(xdg):
    """A directory holding an executable `run` is a valid provider."""
    from credproxy_cli.core.paths import providers_config_dir
    from credproxy_cli.core.providers import find_provider

    d = providers_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    _make_dir_provider(d, "myvault", "#!/bin/sh\necho '{\"value\":\"v\"}'\n")

    p = find_provider("myvault")
    assert p.exe.name == "run"


# ---- fetch: real provider invocation ----------------------------------------


def _user_providers(xdg) -> Path:
    from credproxy_cli.core.paths import providers_config_dir
    d = providers_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_fetch_happy_path(xdg):
    """A well-behaved provider returns the secret value."""
    d = _user_providers(xdg)
    _make_provider(d, "ok_prov", """\
        #!/bin/sh
        python3 -c '
        import json,sys
        req=json.load(sys.stdin)
        json.dump({"values": {r: "hello_secret" for r in req["secrets"]}}, sys.stdout)
        '
    """)

    from credproxy_cli.core.providers import fetch
    value = fetch("ok_prov", "anything")
    assert value == "hello_secret"


def test_fetch_many_batch(xdg):
    """fetch_many resolves every requested ref in one invocation."""
    d = _user_providers(xdg)
    _make_provider(d, "batch_prov", """\
        #!/bin/sh
        python3 -c '
        import json,sys
        req=json.load(sys.stdin)
        json.dump({"values": {r: r.lower() for r in req["secrets"]}}, sys.stdout)
        '
    """)

    from credproxy_cli.core.providers import fetch_many
    out = fetch_many("batch_prov", ["AAA", "BBB"])
    assert out == {"AAA": "aaa", "BBB": "bbb"}


def test_fetch_many_missing_ref(xdg):
    """A response missing a requested ref is a protocol error."""
    d = _user_providers(xdg)
    _make_provider(d, "partial_prov", """\
        #!/bin/sh
        echo '{"values": {"AAA": "x"}}'
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch_many

    with pytest.raises(ProviderError, match="missing ref 'BBB'"):
        fetch_many("partial_prov", ["AAA", "BBB"])


def test_fetch_exit2_not_found(xdg):
    """Exit code 2 -> ProviderError 'not found'."""
    d = _user_providers(xdg)
    _make_provider(d, "notfound_prov", """\
        #!/bin/sh
        exit 2
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="not found"):
        fetch("notfound_prov", "mysecret")


def test_fetch_exit3_unsupported(xdg):
    """Exit code 3 -> ProviderError about unsupported op/version."""
    d = _user_providers(xdg)
    _make_provider(d, "unsup_prov", """\
        #!/bin/sh
        exit 3
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="does not support"):
        fetch("unsup_prov", "mysecret")


def test_fetch_garbage_stdout(xdg):
    """Non-JSON stdout -> ProviderError about non-JSON."""
    d = _user_providers(xdg)
    _make_provider(d, "garbage_prov", """\
        #!/bin/sh
        echo "this is not json at all"
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="non-JSON"):
        fetch("garbage_prov", "mysecret")


def test_fetch_missing_values_object(xdg):
    """JSON without a `values` object -> ProviderError."""
    d = _user_providers(xdg)
    _make_provider(d, "noval_prov", """\
        #!/bin/sh
        echo '{"result":"ok"}'
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="missing a `values` object"):
        fetch("noval_prov", "mysecret")


def test_fetch_value_not_string(xdg):
    """A `values` entry that is not a string -> ProviderError."""
    d = _user_providers(xdg)
    _make_provider(d, "badval_prov", """\
        #!/bin/sh
        echo '{"values": {"mysecret": 42}}'
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="must be a string"):
        fetch("badval_prov", "mysecret")


def test_fetch_nonzero_exit_generic(xdg):
    """Other nonzero exit codes -> generic ProviderError."""
    d = _user_providers(xdg)
    _make_provider(d, "crash_prov", """\
        #!/bin/sh
        exit 5
    """)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="failed.*exit 5"):
        fetch("crash_prov", "mysecret")


# ---- bundled env provider (invoked directly) ---------------------------------


def test_bundled_env_provider_happy_path(xdg, monkeypatch):
    """Invoke the bundled env provider with a real env var."""
    monkeypatch.setenv("TEST_CRED_XYZ", "supersecret")

    from credproxy_cli.core.providers import fetch
    value = fetch("env", "TEST_CRED_XYZ")
    assert value == "supersecret"


def test_bundled_env_provider_not_set(xdg, monkeypatch):
    """Unset env var -> ProviderError (exit 2 path)."""
    monkeypatch.delenv("UNSET_CRED_ZZZQQ", raising=False)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="not found"):
        fetch("env", "UNSET_CRED_ZZZQQ")


# ---- list_providers ----------------------------------------------------------


def test_list_providers_includes_bundled(xdg):
    from credproxy_cli.core.providers import list_providers

    names = [p.name for p in list_providers()]
    assert "env" in names


def test_list_providers_user_shadows(xdg):
    d = _user_providers(xdg)
    _make_provider(d, "env", "#!/bin/sh\necho '{\"value\":\"v\"}'\n")

    from credproxy_cli.core.providers import list_providers
    providers = {p.name: p for p in list_providers()}
    assert providers["env"].source == "user"
