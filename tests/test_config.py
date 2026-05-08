"""Tests for proxy/config.py — YAML schema validation and ${secret:NAME} resolution."""
from pathlib import Path

import pytest

import config


def write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(content)
    return p


# ---- Failure paths (one test per _fail() branch) ----

def test_missing_file(tmp_path):
    with pytest.raises(config.ConfigError, match="missing config file"):
        config.load({}, tmp_path / "absent.yaml")


def test_malformed_yaml(tmp_path):
    p = write_yaml(tmp_path, "key: 'unterminated")
    with pytest.raises(config.ConfigError, match="malformed YAML"):
        config.load({}, p)


def test_missing_top_level_hosts(tmp_path):
    p = write_yaml(tmp_path, "other: {}")
    with pytest.raises(config.ConfigError, match="missing top-level"):
        config.load({}, p)


def test_hosts_not_mapping(tmp_path):
    p = write_yaml(tmp_path, "hosts: [1, 2, 3]")
    with pytest.raises(config.ConfigError, match="`hosts:` must be a mapping"):
        config.load({}, p)


def test_host_entry_not_mapping(tmp_path):
    p = write_yaml(tmp_path, "hosts:\n  api.github.com: 'wrong'")
    with pytest.raises(config.ConfigError, match="hosts.api.github.com must be a mapping"):
        config.load({}, p)


def test_headers_not_mapping(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers: 'wrong'
""")
    with pytest.raises(config.ConfigError, match="headers must be a mapping"):
        config.load({}, p)


def test_header_entry_not_mapping(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization: 'wrong'
""")
    with pytest.raises(config.ConfigError, match="must be a mapping with"):
        config.load({}, p)


@pytest.mark.parametrize("placeholder_yaml", [
    pytest.param('placeholder: ""\n        real: "x"', id="empty"),
    pytest.param('real: "x"', id="missing"),
    pytest.param('placeholder: 42\n        real: "x"', id="non-string"),
])
def test_placeholder_invalid(tmp_path, placeholder_yaml):
    p = write_yaml(tmp_path, f"""
hosts:
  api.github.com:
    headers:
      Authorization:
        {placeholder_yaml}
""")
    with pytest.raises(config.ConfigError, match="placeholder.*non-empty string"):
        config.load({}, p)


@pytest.mark.parametrize("real_yaml", [
    pytest.param('placeholder: "x"\n        real: ""', id="empty"),
    pytest.param('placeholder: "x"', id="missing"),
    pytest.param('placeholder: "x"\n        real: 42', id="non-string"),
])
def test_real_invalid(tmp_path, real_yaml):
    p = write_yaml(tmp_path, f"""
hosts:
  api.github.com:
    headers:
      Authorization:
        {real_yaml}
""")
    with pytest.raises(config.ConfigError, match="real.*non-empty string"):
        config.load({}, p)


def test_unresolved_secret_reference(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: "ph"
        real: "${secret:UNDEFINED}"
""")
    with pytest.raises(config.ConfigError, match="UNDEFINED was not provided"):
        config.load({}, p)


# ---- Happy paths ----

def test_load_minimal_literal_real(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: "ph"
        real: "real_value"
""")
    creds = config.load({}, p)
    assert creds.intercept_hosts() == {"api.github.com"}
    subs = creds.substitutions_for("api.github.com")
    assert len(subs) == 1
    assert subs[0].header == "Authorization"
    assert subs[0].placeholder == "ph"
    assert subs[0].real == "real_value"


def test_load_resolves_secret_reference(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: "ph"
        real: "Bearer ${secret:GITHUB_PAT}"
""")
    creds = config.load({"GITHUB_PAT": "ghp_xxx"}, p)
    [sub] = creds.substitutions_for("api.github.com")
    assert sub.real == "Bearer ghp_xxx"


def test_load_multiple_secret_references_in_one_value(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      X-Compound:
        placeholder: "ph"
        real: "${secret:A}/${secret:B}"
""")
    creds = config.load({"A": "alpha", "B": "bravo"}, p)
    [sub] = creds.substitutions_for("api.github.com")
    assert sub.real == "alpha/bravo"


def test_load_intercept_only_no_headers(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  example.com: {}
  api.github.com:
    headers: {}
""")
    creds = config.load({}, p)
    assert creds.intercept_hosts() == {"example.com", "api.github.com"}
    assert creds.substitutions_for("example.com") == []
    assert creds.substitutions_for("api.github.com") == []


def test_workspace_tokens_shape(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: "ph1"
        real: "r1"
      X-Custom:
        placeholder: "ph2"
        real: "r2"
  api.example.com:
    headers:
      X-API-Key:
        placeholder: "ph3"
        real: "r3"
""")
    creds = config.load({}, p)
    assert creds.workspace_tokens() == {
        "api.github.com": {"Authorization": "ph1", "X-Custom": "ph2"},
        "api.example.com": {"X-API-Key": "ph3"},
    }


def test_substitutions_for_unknown_host_returns_empty(tmp_path):
    p = write_yaml(tmp_path, """
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: "ph"
        real: "r"
""")
    creds = config.load({}, p)
    assert creds.substitutions_for("not-configured.com") == []


# ---- load_resolved (parse-only path used by /admin/config) ----

def test_load_resolved_minimal():
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


def test_load_resolved_rejects_unresolved_secret_reference():
    """No secrets dict is provided, so any ${secret:NAME} fails the resolver."""
    with pytest.raises(config.ConfigError, match="GITHUB_PAT was not provided"):
        config.load_resolved({
            "hosts": {
                "api.github.com": {
                    "headers": {
                        "Authorization": {
                            "placeholder": "ph",
                            "real": "${secret:GITHUB_PAT}",
                        }
                    }
                }
            }
        })


def test_load_resolved_validation_errors_use_source_label():
    """Default source label should appear in error messages, replacing path."""
    with pytest.raises(config.ConfigError, match="<resolved>"):
        config.load_resolved({"not-hosts": {}})


def test_load_resolved_custom_source_label():
    with pytest.raises(config.ConfigError, match="POST /admin/config"):
        config.load_resolved({"not-hosts": {}}, source="POST /admin/config")
