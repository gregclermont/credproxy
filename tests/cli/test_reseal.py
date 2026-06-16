"""CLI-side coverage for the re-seal injectors: the built-in
oauth2-reseal scheme in the catalog, the scripted oauth-reseal twin, list-valued
params (api_hosts), and the wire shape.
"""
import textwrap

import pytest


def _write_injector(name: str, body: str):
    from credproxy_cli.core.paths import injectors_config_dir
    d = injectors_config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.toml").write_text(textwrap.dedent(body))


def test_builtin_oauth2_reseal_injector(xdg):
    from credproxy_cli.core.injectors import find_injector

    inj = find_injector("oauth2-reseal")
    assert inj.scheme == "oauth2-reseal"
    assert inj.spec.family == "substitute"
    assert inj.spec.location_kind == "body"
    assert inj.spec.uses_placeholder is True
    assert inj.params["api_hosts"] == ["api.example.com"]
    assert inj.params["token_field"] == "access_token"


def test_builtin_oauth_reseal_scripted_injector(xdg):
    from credproxy_cli.core.injectors import find_injector
    from credproxy_cli.core.scripts import find_script

    inj = find_injector("oauth-reseal")
    assert inj.scheme == "script" and inj.script == "oauth-reseal"
    assert inj.spec.location_kind == "body"
    assert inj.params["api_hosts"] == ["api.example.com"]
    assert "mint_into_json" in find_script("oauth-reseal").source


def test_reseal_wire_includes_api_hosts_list(xdg, workspaces_dir):
    from credproxy_cli.core.bindings import Binding, wire_config

    b = Binding(name="oauth", injector="oauth2-reseal", provider="env", secret="CS",
                hosts=("login.example.com",), placeholder="credproxy_xxxxxxxxxxxx",
                env=None)
    wire = wire_config([b], fetch_many=lambda p, refs: {r: "REAL" for r in refs})
    e = wire["bindings"][0]
    assert e["scheme"] == "oauth2-reseal"
    assert e["params"]["api_hosts"] == ["api.example.com"]
    assert e["secret"] == {"value": "REAL"}
    assert e["placeholder"] == "credproxy_xxxxxxxxxxxx"


def test_list_param_rejects_non_strings(xdg):
    _write_injector("badlist", """
        scheme = "oauth2-reseal"
        [params]
        api_hosts = [1, 2]
    """)
    from credproxy_cli.core.errors import InjectorError
    from credproxy_cli.core.injectors import find_injector

    with pytest.raises(InjectorError, match="string or array of strings"):
        find_injector("badlist")
