"""Tests for core/providers.py: registry lookup, protocol invocation against
real test provider scripts, builtin env provider, and error paths."""
from __future__ import annotations

import json
import os
import shutil
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


def test_find_builtin_env(xdg):
    from credproxy_cli.core.providers import find_provider

    p = find_provider("env")
    assert p.name == "env"
    assert p.source == "builtin"
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


def test_find_provider_user_shadows_builtin(xdg):
    """A user provider with the same name as a builtin one takes precedence."""
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


# ---- builtin env provider (invoked directly) ---------------------------------


def test_builtin_env_provider_happy_path(xdg, monkeypatch):
    """Invoke the builtin env provider with a real env var."""
    monkeypatch.setenv("TEST_CRED_XYZ", "supersecret")

    from credproxy_cli.core.providers import fetch
    value = fetch("env", "TEST_CRED_XYZ")
    assert value == "supersecret"


def test_builtin_env_provider_not_set(xdg, monkeypatch):
    """Unset env var -> ProviderError (exit 2 path)."""
    monkeypatch.delenv("UNSET_CRED_ZZZQQ", raising=False)

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch

    with pytest.raises(ProviderError, match="not found"):
        fetch("env", "UNSET_CRED_ZZZQQ")


# ---- builtin bw provider (fake `bw` on PATH, no real CLI needed) --------------


def _fake_bw(tmp_path, items, *, status="unlocked") -> Path:
    """Write a fake `bw` onto a fresh bin dir and return the call-log path.
    Answers `status`/`list items`; logs every invocation so a test can assert
    how many times the vault was actually read."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    calls = tmp_path / "bw-calls.log"
    bw = fake_bin / "bw"
    bw.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"open({str(calls)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        "arg = sys.argv[1] if len(sys.argv) > 1 else ''\n"
        f"if arg == 'status': print({json.dumps(json.dumps({'status': status}))})\n"
        f"elif arg == 'list': print({json.dumps(json.dumps(items))})\n"
        "else: sys.exit(1)\n"
    )
    bw.chmod(0o755)
    return fake_bin, calls


def test_builtin_bw_provider_batches_and_extracts(xdg, monkeypatch, tmp_path):
    """One `bw list items` resolves a whole multi-ref batch, across password /
    username / custom-field selectors -- the provider-side half of the batching
    win (the costly vault decrypt happens once, not once per ref)."""
    items = [
        {"id": "id-gh", "name": "github",
         "login": {"username": "octocat", "password": "ghp_tok", "uris": []},
         "fields": []},
        {"id": "id-aws", "name": "aws-prod", "login": {},
         "fields": [{"name": "access_key_id", "value": "AKIA"},
                    {"name": "secret_access_key", "value": "wJalr"}]},
    ]
    fake_bin, calls = _fake_bw(tmp_path, items)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.providers import fetch_many
    vals = fetch_many("bw", ["github", "github#username",
                             "aws-prod#access_key_id", "aws-prod#secret_access_key"])
    assert vals == {
        "github": "ghp_tok",
        "github#username": "octocat",
        "aws-prod#access_key_id": "AKIA",
        "aws-prod#secret_access_key": "wJalr",
    }
    # The whole batch -> a single vault read, however many refs were requested.
    assert calls.read_text().splitlines().count("list items") == 1


def test_builtin_bw_provider_missing_item_exit2(xdg, monkeypatch, tmp_path):
    """An unknown item is a not-found (exit 2) -> ProviderError, not a crash."""
    fake_bin, _ = _fake_bw(tmp_path, [{"id": "id-gh", "name": "github",
                                       "login": {"password": "x"}, "fields": []}])
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch
    with pytest.raises(ProviderError, match="not found"):
        fetch("bw", "ghost")


# ---- builtin gh-cli provider (fake `gh` on PATH, no real CLI needed) ----------


def _fake_gh(tmp_path, *, token="gho_faketoken", known=("github.com",)) -> Path:
    """Write a fake `gh` onto a fresh bin dir, logging argv. `auth token` prints
    the token for a known `--hostname` (or no hostname = default host); an
    unknown host exits 1 like a missing login."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    calls = tmp_path / "gh-calls.log"
    gh = fake_bin / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"open({str(calls)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        "a = sys.argv[1:]\n"
        "if a[:2] != ['auth', 'token']: sys.exit(2)\n"
        "host = a[a.index('--hostname') + 1] if '--hostname' in a else ''\n"
        f"known = set({list(known)!r}) | {{''}}\n"
        f"print({token!r}) if host in known else sys.exit(1)\n"
    )
    gh.chmod(0o755)
    return fake_bin, calls


def test_builtin_gh_cli_provider_returns_token(xdg, monkeypatch, tmp_path):
    """gh-cli resolves a hostname ref to the token and passes `--hostname`."""
    fake_bin, calls = _fake_gh(tmp_path, token="gho_realtoken")
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.providers import fetch
    assert fetch("gh-cli", "github.com") == "gho_realtoken"
    assert "auth token --hostname github.com" in calls.read_text()


def test_builtin_gh_cli_provider_empty_ref_default_host(xdg, monkeypatch, tmp_path):
    """An empty ref uses gh's default host -- no `--hostname` is passed."""
    fake_bin, calls = _fake_gh(tmp_path)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.providers import fetch
    assert fetch("gh-cli", "") == "gho_faketoken"
    assert "--hostname" not in calls.read_text()


def test_builtin_gh_cli_provider_dedups_repeated_host(xdg, monkeypatch, tmp_path):
    """A host requested twice in one batch shells out to `gh` only once."""
    fake_bin, calls = _fake_gh(tmp_path)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.providers import fetch_many
    vals = fetch_many("gh-cli", ["github.com", "github.com"])
    assert vals == {"github.com": "gho_faketoken"}
    assert calls.read_text().count("auth token") == 1


def test_builtin_gh_cli_provider_unknown_host_exit2(xdg, monkeypatch, tmp_path):
    """A host with no login is a not-found (exit 2) -> ProviderError."""
    fake_bin, _ = _fake_gh(tmp_path, known=("github.com",))
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch
    with pytest.raises(ProviderError, match="not found"):
        fetch("gh-cli", "ghe.example.invalid")


# ---- builtin docker-credential provider (fake helper + DOCKER_CONFIG) ---------


def _fake_docker_helper(tmp_path, creds, *, helper="faux", creds_store=None,
                        cred_helpers=None) -> Path:
    """Write a fake `docker-credential-<helper>` on a fresh bin dir and a
    DOCKER_CONFIG/config.json. The binary name (`helper`) is independent of the
    config's `credsStore` (defaults to `helper`) and `credHelpers`, so a test
    can point credHelpers at the real binary while credsStore names a missing
    one. The helper reads the host on stdin and emits the helper-protocol JSON
    for a known host, exiting 1 otherwise; it logs each invocation. Returns
    (bin_dir, config_dir, calls_log)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    cfg_dir = tmp_path / "docker"
    cfg_dir.mkdir(exist_ok=True)
    calls = tmp_path / "helper-calls.log"
    exe = bin_dir / f"docker-credential-{helper}"
    exe.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        f"open({str(calls)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        "host = sys.stdin.read().strip()\n"
        f"creds = {json.dumps(creds)}\n"
        "if sys.argv[1:2] != ['get'] or host not in creds: sys.exit(1)\n"
        "json.dump({'ServerURL': host, 'Username': 'u', 'Secret': creds[host]},"
        " sys.stdout)\n"
    )
    exe.chmod(0o755)
    config = {"credsStore": creds_store if creds_store is not None else helper}
    if cred_helpers:
        config["credHelpers"] = cred_helpers
    (cfg_dir / "config.json").write_text(json.dumps(config))
    return bin_dir, cfg_dir, calls


def _use_docker(monkeypatch, bin_dir, cfg_dir):
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))


def test_docker_credential_explicit_helper(xdg, monkeypatch, tmp_path):
    """`<helper>|<host>` runs that helper and returns its Secret -- no config
    lookup needed."""
    bin_dir, cfg_dir, _ = _fake_docker_helper(tmp_path, {"ghcr.io": "ghp_sekret"})
    _use_docker(monkeypatch, bin_dir, cfg_dir)

    from credproxy_cli.core.providers import fetch
    assert fetch("docker-credential", "faux|ghcr.io") == "ghp_sekret"


def test_docker_credential_auto_credsstore(xdg, monkeypatch, tmp_path):
    """A bare host resolves its helper from credsStore in the docker config."""
    bin_dir, cfg_dir, _ = _fake_docker_helper(tmp_path, {"ghcr.io": "tok"})
    _use_docker(monkeypatch, bin_dir, cfg_dir)

    from credproxy_cli.core.providers import fetch
    assert fetch("docker-credential", "ghcr.io") == "tok"


def test_docker_credential_auto_credhelpers_wins(xdg, monkeypatch, tmp_path):
    """credHelpers[host] takes precedence over credsStore for the helper name."""
    # binary is docker-credential-faux; credsStore names a MISSING helper, so a
    # `tok` result proves credHelpers[ghcr.io]=faux was used, not credsStore.
    bin_dir, cfg_dir, _ = _fake_docker_helper(
        tmp_path, {"ghcr.io": "tok"}, helper="faux", creds_store="missing-store",
        cred_helpers={"ghcr.io": "faux"})
    _use_docker(monkeypatch, bin_dir, cfg_dir)

    from credproxy_cli.core.providers import fetch
    assert fetch("docker-credential", "ghcr.io") == "tok"


def test_docker_credential_no_helper_for_host_exit2(xdg, monkeypatch, tmp_path):
    """A bare host with no credHelpers/credsStore entry is a not-found."""
    (tmp_path / "docker").mkdir()  # empty config dir -> no config.json
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker"))

    from credproxy_cli.core.errors import ProviderError
    from credproxy_cli.core.providers import fetch
    with pytest.raises(ProviderError, match="not found"):
        fetch("docker-credential", "ghcr.io")


def test_docker_credential_dedups_same_helper_host(xdg, monkeypatch, tmp_path):
    """`ghcr.io` and `faux|ghcr.io` resolve to the same (helper, host), so the
    helper runs once even though they are distinct ref strings."""
    bin_dir, cfg_dir, calls = _fake_docker_helper(tmp_path, {"ghcr.io": "tok"})
    _use_docker(monkeypatch, bin_dir, cfg_dir)

    from credproxy_cli.core.providers import fetch_many
    vals = fetch_many("docker-credential", ["ghcr.io", "faux|ghcr.io"])
    assert vals == {"ghcr.io": "tok", "faux|ghcr.io": "tok"}
    assert calls.read_text().count("get") == 1


# ---- list_providers ----------------------------------------------------------


def test_list_providers_includes_builtin(xdg):
    from credproxy_cli.core.providers import list_providers

    names = [p.name for p in list_providers()]
    assert "env" in names


def test_list_providers_user_shadows(xdg):
    d = _user_providers(xdg)
    _make_provider(d, "env", "#!/bin/sh\necho '{\"value\":\"v\"}'\n")

    from credproxy_cli.core.providers import list_providers
    providers = {p.name: p for p in list_providers()}
    assert providers["env"].source == "user"


# ---- description via the `describe` op (provider IS executed on `list`) -------


def test_builtin_providers_describe(xdg):
    from credproxy_cli.core.providers import list_providers
    desc = {p.name: p.description for p in list_providers()}
    assert desc["env"] == "Host environment variables"
    assert desc["op"] == "1Password (op CLI)"
    assert desc["keychain"]  # non-empty
    # bw's describe is static -- it must NOT shell out to `bw` (so `provider
    # list` never pops an unlock prompt), hence this passes with no bw on PATH.
    assert desc["bw"] == "Bitwarden (bw CLI)"
    # gh-cli's describe is likewise static (no `gh` call on list).
    assert desc["gh-cli"] == "GitHub auth token (gh CLI)"
    # docker-credential's describe reads neither the docker config nor a helper.
    assert desc["docker-credential"] == "Docker credential helper (registry auth)"


def test_user_provider_describe_supported(xdg):
    d = _user_providers(xdg)
    _make_provider(d, "fancy",
                   "#!/usr/bin/env python3\n"
                   "import json, sys\n"
                   "req = json.load(sys.stdin)\n"
                   "if req.get('op') == 'describe':\n"
                   "    json.dump({'description': 'A fancy provider'}, sys.stdout)\n"
                   "    sys.exit(0)\n"
                   "sys.exit(3)\n")
    from credproxy_cli.core.providers import list_providers
    desc = {p.name: p.description for p in list_providers()}
    assert desc["fancy"] == "A fancy provider"


def test_provider_without_describe_is_none(xdg):
    """A provider that doesn't implement describe (exits 3) lists with no
    description -- graceful, so old providers keep working."""
    d = _user_providers(xdg)
    _make_provider(d, "plain", "#!/bin/sh\nexit 3\n")
    from credproxy_cli.core.providers import list_providers
    desc = {p.name: p.description for p in list_providers()}
    assert desc["plain"] is None


def test_describe_non_json_is_none(xdg):
    from credproxy_cli.core.providers import _describe
    d = _user_providers(xdg)
    p = _make_provider(d, "garbage", "#!/bin/sh\necho not-json\n")  # exit 0, junk
    assert _describe(p) is None


# ---- help op + `provider show` -----------------------------------------------


def test_help_op_builtin(xdg):
    from credproxy_cli.core.providers import find_provider, _help
    h = _help(find_provider("op").exe)
    assert h and "op://" in h  # the ref format is in the help


def test_help_unsupported_is_none(xdg):
    """A provider that implements describe but not help -> help is None."""
    d = _user_providers(xdg)
    _make_provider(d, "deso",
                   "#!/usr/bin/env python3\n"
                   "import json, sys\n"
                   "req = json.load(sys.stdin)\n"
                   "if req.get('op') == 'describe':\n"
                   "    json.dump({'description': 'desc only'}, sys.stdout)\n"
                   "    sys.exit(0)\n"
                   "sys.exit(3)\n")
    from credproxy_cli.core.providers import find_provider, _help
    assert _help(find_provider("deso").exe) is None


def test_provider_show_human(xdg):
    from test_porcelain import _run
    code, out, err = _run(["provider", "show", "op"])
    assert code == 0
    blob = out + err
    assert "builtin" in blob
    assert "/providers/op" in blob          # the resolved path is shown
    assert "op://" in blob                   # help text is shown


def test_provider_show_json(xdg):
    from test_porcelain import _run
    code, out, err = _run(["--json", "provider", "show", "keychain"])
    assert code == 0
    d = json.loads(out)
    assert d["name"] == "keychain"
    assert d["path"].endswith("/keychain")
    assert d["source"] == "builtin"
    assert d["description"] and d["help"]


def test_provider_show_missing(xdg):
    from test_porcelain import _run
    code, out, err = _run(["provider", "show", "nope_zzz"])
    assert code == 1


# ---- provider scaffold --lang ------------------------------------------------


def test_scaffold_lang_default_python(xdg):
    from test_porcelain import _run
    from credproxy_cli.core.paths import providers_config_dir
    assert _run(["provider", "scaffold", "pyprov"])[0] == 0
    text = (providers_config_dir() / "pyprov").read_text()
    assert text.startswith("#!/usr/bin/env python3")


def test_scaffold_lang_sh(xdg):
    from test_porcelain import _run
    from credproxy_cli.core.paths import providers_config_dir
    assert _run(["provider", "scaffold", "myvault", "--lang", "sh"])[0] == 0
    p = providers_config_dir() / "myvault"
    text = p.read_text()
    assert text.startswith("#!/bin/sh")
    assert "fetch()" in text and "PROTOCOL_VERSION=1" in text
    assert os.access(p, os.X_OK)


def test_scaffold_lang_unknown(xdg):
    from test_porcelain import _run
    code, out, err = _run(["provider", "scaffold", "z", "--lang", "ruby"])
    assert code == 1
    assert "python or sh" in (out + err)


def test_scaffold_lang_rejected_on_injector(xdg):
    from test_porcelain import _run
    code, out, err = _run(["injector", "scaffold", "z", "--lang", "sh"])
    assert code == 1
    assert "only valid for" in (out + err)


@pytest.mark.skipif(shutil.which("jq") is None, reason="sh provider needs jq")
def test_scaffold_sh_provider_runs_via_cli(xdg, monkeypatch):
    """The scaffolded shell provider works end-to-end through the CLI: describe
    (provider show) and a real fetch (binding test)."""
    from test_porcelain import _run
    assert _run(["provider", "scaffold", "shp", "--lang", "sh"])[0] == 0
    code, out, err = _run(["provider", "show", "shp"])
    assert code == 0 and "Host environment variables" in (out + err)
    monkeypatch.setenv("SHX", "abcdef")
    code, out, err = _run(["workspace", "binding", "test", "--provider", "shp",
                           "--secret", "SHX", "--injector", "bearer"])
    assert code == 0 and "value length 6" in (out + err)


def _scaffold_sh_provider(name: str) -> Path:
    from credproxy_cli.core.scaffold import scaffold
    return scaffold("provider", name, "sh").path


@pytest.mark.skipif(shutil.which("jq") is None, reason="sh provider needs jq")
def test_sh_provider_ref_with_space_not_split(xdg, monkeypatch):
    """A ref containing a space (common for op/bw/keychain item names) must be
    treated as ONE ref, not word-split -- and multiple refs still accumulate
    (the loop runs in the pipe subshell where it also emits)."""
    import subprocess
    prov = _scaffold_sh_provider("shp")
    monkeypatch.setenv("My Token", "SPACED")
    monkeypatch.setenv("PLAIN", "p")
    req = json.dumps({"version": 1, "op": "get", "secrets": ["My Token", "PLAIN"]})
    r = subprocess.run([str(prov)], input=req, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["values"] == {"My Token": "SPACED", "PLAIN": "p"}


@pytest.mark.skipif(shutil.which("jq") is None, reason="sh provider needs jq")
def test_sh_provider_missing_ref_fails_closed(xdg):
    """A fetch failure must propagate exit 2 out of the pipe subshell (the
    `|| exit $?` guard), so a missing secret blocks the push -- never exits 0."""
    import subprocess
    prov = _scaffold_sh_provider("shp")
    req = json.dumps({"version": 1, "op": "get", "secrets": ["DEFINITELY_UNSET_XYZ"]})
    r = subprocess.run([str(prov)], input=req, capture_output=True, text=True)
    assert r.returncode == 2
