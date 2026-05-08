"""Tests for proxy/config.py — load_resolved schema validation.

The proxy receives an already-resolved config dict; secret resolution
happens client-side (bin/credproxy). config.load_resolved validates the
shape and produces a YamlCredentials.
"""
import pytest

import config


# ---- Failure paths (one test per _fail() branch in _build) ----

def test_non_dict_input():
    with pytest.raises(config.ConfigError, match="missing top-level"):
        config.load_resolved("not a dict")


def test_missing_top_level_hosts():
    with pytest.raises(config.ConfigError, match="missing top-level"):
        config.load_resolved({"other": {}})


def test_hosts_not_mapping():
    with pytest.raises(config.ConfigError, match="`hosts:` must be a mapping"):
        config.load_resolved({"hosts": [1, 2, 3]})


def test_host_entry_not_mapping():
    with pytest.raises(config.ConfigError, match="hosts.api.github.com must be a mapping"):
        config.load_resolved({"hosts": {"api.github.com": "wrong"}})


def test_headers_not_mapping():
    with pytest.raises(config.ConfigError, match="headers must be a mapping"):
        config.load_resolved({"hosts": {"api.github.com": {"headers": "wrong"}}})


def test_header_entry_not_mapping():
    with pytest.raises(config.ConfigError, match="must be a mapping with"):
        config.load_resolved({
            "hosts": {"api.github.com": {"headers": {"Authorization": "wrong"}}}
        })


@pytest.mark.parametrize("placeholder", [
    pytest.param("", id="empty"),
    pytest.param(None, id="missing"),
    pytest.param(42, id="non-string"),
])
def test_placeholder_invalid(placeholder):
    entry = {"real": "x"}
    if placeholder is not None:
        entry["placeholder"] = placeholder
    with pytest.raises(config.ConfigError, match="placeholder.*non-empty string"):
        config.load_resolved({
            "hosts": {"api.github.com": {"headers": {"Authorization": entry}}}
        })


@pytest.mark.parametrize("real", [
    pytest.param("", id="empty"),
    pytest.param(None, id="missing"),
    pytest.param(42, id="non-string"),
])
def test_real_invalid(real):
    entry = {"placeholder": "x"}
    if real is not None:
        entry["real"] = real
    with pytest.raises(config.ConfigError, match="real.*non-empty string"):
        config.load_resolved({
            "hosts": {"api.github.com": {"headers": {"Authorization": entry}}}
        })


def test_unresolved_secret_reference_rejected():
    """Unresolved ${secret:NAME} in real -> 400. Caller resolves client-side."""
    with pytest.raises(config.ConfigError, match="unresolved \\$\\{secret:GITHUB_PAT\\}"):
        config.load_resolved({
            "hosts": {
                "api.github.com": {
                    "headers": {
                        "Authorization": {
                            "placeholder": "ph",
                            "real": "Bearer ${secret:GITHUB_PAT}",
                        }
                    }
                }
            }
        })


def test_validation_uses_source_label():
    with pytest.raises(config.ConfigError, match="POST /admin/config"):
        config.load_resolved({"not-hosts": {}}, source="POST /admin/config")


def test_default_source_label():
    with pytest.raises(config.ConfigError, match="<resolved>"):
        config.load_resolved({"not-hosts": {}})


# ---- Happy paths ----

def test_minimal_config():
    creds = config.load_resolved({
        "hosts": {
            "api.github.com": {
                "headers": {
                    "Authorization": {
                        "placeholder": "ph",
                        "real": "real_value",
                    }
                }
            }
        }
    })
    assert creds.intercept_hosts() == {"api.github.com"}
    [sub] = creds.substitutions_for("api.github.com")
    assert (sub.header, sub.placeholder, sub.real) == ("Authorization", "ph", "real_value")


def test_intercept_only_no_headers():
    creds = config.load_resolved({
        "hosts": {
            "example.com": {},
            "api.github.com": {"headers": {}},
        }
    })
    assert creds.intercept_hosts() == {"example.com", "api.github.com"}
    assert creds.substitutions_for("example.com") == []
    assert creds.substitutions_for("api.github.com") == []


def test_workspace_tokens_shape():
    creds = config.load_resolved({
        "hosts": {
            "api.github.com": {
                "headers": {
                    "Authorization": {"placeholder": "ph1", "real": "r1"},
                    "X-Custom": {"placeholder": "ph2", "real": "r2"},
                }
            },
            "api.example.com": {
                "headers": {
                    "X-API-Key": {"placeholder": "ph3", "real": "r3"},
                }
            },
        }
    })
    assert creds.workspace_tokens() == {
        "api.github.com": {"Authorization": "ph1", "X-Custom": "ph2"},
        "api.example.com": {"X-API-Key": "ph3"},
    }


def test_substitutions_for_unknown_host_returns_empty():
    creds = config.load_resolved({
        "hosts": {
            "api.github.com": {
                "headers": {
                    "Authorization": {"placeholder": "ph", "real": "r"}
                }
            }
        }
    })
    assert creds.substitutions_for("not-configured.com") == []


def test_empty_credentials_no_intercepts():
    """YamlCredentials({}) is the legitimate startup state when no
    config has been pushed yet."""
    creds = config.YamlCredentials({})
    assert creds.intercept_hosts() == set()
    assert creds.workspace_tokens() == {}
    assert creds.substitutions_for("anything.example") == []
