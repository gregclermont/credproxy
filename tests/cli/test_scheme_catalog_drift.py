"""Guard against drift between the CLI scheme catalog and the proxy registry.

core/schemes.CATALOG duplicates, by necessity, knowledge that lives in
proxy/schemes.SCHEMES (the CLI can't import proxy code). These tests import
BOTH (proxy/schemes.py and proxy/config.py have no mitmproxy dependency, so
they load on the host) and assert the two stay in sync -- the same role the
RESERVED_NAMES guard test plays for the CLI verbs.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _proxy():
    """Import the proxy's schemes + config modules on the host."""
    proxy_dir = str(Path(__file__).resolve().parents[2] / "proxy")
    if proxy_dir not in sys.path:
        sys.path.insert(0, proxy_dir)
    import config as proxy_config
    import schemes as proxy_schemes
    return proxy_schemes, proxy_config


def test_catalog_keys_match_proxy_registry():
    from credproxy_cli.core import schemes as cli_schemes
    proxy_schemes, _ = _proxy()
    assert set(cli_schemes.CATALOG) == set(proxy_schemes.SCHEMES)


def test_family_and_slots_match():
    from credproxy_cli.core import schemes as cli_schemes
    proxy_schemes, _ = _proxy()
    for name, spec in cli_schemes.CATALOG.items():
        s = proxy_schemes.SCHEMES[name]
        assert spec.family == s.family, f"family mismatch for {name}"
        assert tuple(spec.slots) == tuple(s.slots), f"slots mismatch for {name}"


def test_location_key_matches_proxy():
    """The CLI's collision check and the proxy's must agree for every scheme,
    using each scheme's default params."""
    from credproxy_cli.core import schemes as cli_schemes
    _, proxy_config = _proxy()
    for name, spec in cli_schemes.CATALOG.items():
        params = dict(spec.param_defaults)
        assert cli_schemes.location_key(spec, params) == \
            proxy_config._location_key(name, params), f"location_key mismatch for {name}"
