"""Tests for proxy/config.py — load_resolved schema validation.

The proxy receives an already-resolved config dict (bindings wire format,
scheme-aware); secret resolution happens client-side (bin/credproxy).
config.load_resolved validates the shape and produces a BindingCredentials.
"""
import pytest

import config


def _entry(**over):
    """A valid bearer binding entry; override fields per test."""
    e = {
        "name": "b",
        "hosts": ["api.github.com"],
        "scheme": "bearer",
        "params": {"header": "Authorization"},
        "secret": {"value": "real_value"},
        "placeholder": "ph",
    }
    e.update(over)
    return e


# ---- Failure paths (one test per _fail() branch in load_resolved) ----

def test_non_dict_input():
    with pytest.raises(config.ConfigError, match="missing top-level"):
        config.load_resolved("not a dict")


def test_missing_top_level_bindings():
    with pytest.raises(config.ConfigError, match="missing top-level"):
        config.load_resolved({"other": {}})


def test_bindings_not_array():
    with pytest.raises(config.ConfigError, match="`bindings` must be an array"):
        config.load_resolved({"bindings": {"not": "an-array"}})


def test_binding_entry_not_object():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\] must be an object"):
        config.load_resolved({"bindings": ["wrong"]})


def test_name_missing():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].name must be a non-empty string"):
        config.load_resolved({"bindings": [_entry(name=None)]})


def test_name_empty():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].name must be a non-empty string"):
        config.load_resolved({"bindings": [_entry(name="")]})


def test_name_duplicate():
    with pytest.raises(config.ConfigError, match="duplicate binding name 'dup'"):
        config.load_resolved({"bindings": [
            _entry(name="dup"),
            _entry(name="dup", hosts=["api.example.com"]),
        ]})


def test_hosts_missing():
    e = _entry()
    del e["hosts"]
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].hosts must be a non-empty array"):
        config.load_resolved({"bindings": [e]})


def test_hosts_empty_array():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].hosts must be a non-empty array"):
        config.load_resolved({"bindings": [_entry(hosts=[])]})


def test_hosts_not_array():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].hosts must be a non-empty array"):
        config.load_resolved({"bindings": [_entry(hosts="api.github.com")]})


def test_scheme_missing():
    e = _entry()
    del e["scheme"]
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].scheme must be one of"):
        config.load_resolved({"bindings": [e]})


def test_scheme_unknown():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].scheme must be one of"):
        config.load_resolved({"bindings": [_entry(scheme="telepathy")]})


def test_params_not_object():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].params must be an object"):
        config.load_resolved({"bindings": [_entry(params="nope")]})


def test_params_value_non_string_rejected():
    with pytest.raises(config.ConfigError, match=r"params\['header'\] must be a string"):
        config.load_resolved({"bindings": [_entry(params={"header": 123})]})


def test_extra_secret_slot_rejected():
    """The proxy rejects unknown slots (symmetric with the CLI), so stray real
    values are never held in memory."""
    with pytest.raises(config.ConfigError, match="needs secret slot"):
        config.load_resolved({"bindings": [_entry(secret={"value": "t", "extra": "x"})]})


@pytest.mark.parametrize("placeholder", [
    pytest.param("", id="empty"),
    pytest.param(None, id="missing"),
    pytest.param(42, id="non-string"),
])
def test_placeholder_invalid_for_substitute(placeholder):
    e = _entry()
    if placeholder is None:
        del e["placeholder"]
    else:
        e["placeholder"] = placeholder
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].placeholder must be a non-empty string"):
        config.load_resolved({"bindings": [e]})


def test_secret_missing():
    e = _entry()
    del e["secret"]
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].secret must be a non-empty object"):
        config.load_resolved({"bindings": [e]})


def test_secret_not_object():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].secret must be a non-empty object"):
        config.load_resolved({"bindings": [_entry(secret="raw")]})


@pytest.mark.parametrize("val", [
    pytest.param("", id="empty"),
    pytest.param(42, id="non-string"),
])
def test_secret_value_invalid(val):
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].secret\['value'\] must be a non-empty string"):
        config.load_resolved({"bindings": [_entry(secret={"value": val})]})


def test_secret_missing_required_slot():
    """sigv4-style multi-slot need is enforced via the scheme's slots; a
    bearer with the wrong slot name is missing `value`."""
    with pytest.raises(config.ConfigError, match="needs secret slot"):
        config.load_resolved({"bindings": [_entry(secret={"wrong": "x"})]})


def test_unresolved_secret_reference_in_value_rejected():
    with pytest.raises(config.ConfigError, match=r"unresolved \$\{secret:GITHUB_PAT\}"):
        config.load_resolved({"bindings": [
            _entry(secret={"value": "Bearer ${secret:GITHUB_PAT}"})
        ]})


def test_unresolved_secret_reference_in_placeholder_rejected():
    with pytest.raises(config.ConfigError, match=r"unresolved \$\{secret:GITHUB_PH\}"):
        config.load_resolved({"bindings": [_entry(placeholder="${secret:GITHUB_PH}")]})


def test_env_empty_string_rejected():
    with pytest.raises(config.ConfigError, match=r"bindings\[0\].env must be a non-empty string or absent/null"):
        config.load_resolved({"bindings": [_entry(env="")]})


def test_host_location_same_placeholder_collides():
    """Two bindings writing the same header on the same host with the SAME
    placeholder can't be told apart -> ConfigError."""
    with pytest.raises(config.ConfigError, match="both write header on host"):
        config.load_resolved({"bindings": [
            _entry(name="b1", placeholder="ph"),
            _entry(name="b2", placeholder="ph"),
        ]})


def test_host_location_distinct_placeholders_allowed():
    """Distinct placeholders disambiguate, so two bindings may share a header on
    one host (each swaps only its own placeholder) -- what lets several re-seal
    bindings share a token endpoint."""
    creds = config.load_resolved({"bindings": [
        _entry(name="b1", placeholder="ph1"),
        _entry(name="b2", placeholder="ph2"),
    ]})
    assert len(creds.transforms_for("api.github.com")) == 2


def test_unconditional_writers_collide():
    """Two no-placeholder (sign) bindings on the same header write
    unconditionally -- nothing disambiguates them, so they collide."""
    sig = {"name": "s1", "hosts": ["aws.example.com"], "scheme": "sigv4",
           "secret": {"access_key_id": "AK", "secret_access_key": "SK"}}
    with pytest.raises(config.ConfigError, match="no placeholder"):
        config.load_resolved({"bindings": [sig, {**sig, "name": "s2"}]})


def test_validation_uses_source_label():
    with pytest.raises(config.ConfigError, match="POST /admin/config"):
        config.load_resolved({"not-bindings": {}}, source="POST /admin/config")


def test_default_source_label():
    with pytest.raises(config.ConfigError, match="<resolved>"):
        config.load_resolved({"not-bindings": {}})


# ---- Happy paths ----

def test_minimal_config():
    creds = config.load_resolved({"bindings": [
        _entry(name="github-env", placeholder="ph", secret={"value": "real_value"})
    ]})
    assert creds.intercept_hosts() == {"api.github.com"}
    [t] = creds.transforms_for("api.github.com")
    assert t.scheme.name == "bearer"
    assert t.placeholder == "ph"
    assert t.secrets == {"value": "real_value"}
    assert t.params == {"header": "Authorization"}


def test_params_optional_defaults_empty():
    e = _entry()
    del e["params"]
    creds = config.load_resolved({"bindings": [e]})
    [t] = creds.transforms_for("api.github.com")
    assert t.params == {}


def test_env_optional_null():
    creds = config.load_resolved({"bindings": [_entry(env=None)]})
    [ib] = creds.inward_bindings()
    assert ib.env is None


def test_env_optional_absent():
    e = _entry()
    creds = config.load_resolved({"bindings": [e]})
    [ib] = creds.inward_bindings()
    assert ib.env is None


def test_env_present():
    creds = config.load_resolved({"bindings": [_entry(env="GITHUB_TOKEN")]})
    [ib] = creds.inward_bindings()
    assert ib.env == "GITHUB_TOKEN"


def test_multiple_hosts_in_one_binding():
    creds = config.load_resolved({"bindings": [
        _entry(hosts=["api.github.com", "uploads.github.com"])
    ]})
    assert creds.intercept_hosts() == {"api.github.com", "uploads.github.com"}
    assert len(creds.transforms_for("api.github.com")) == 1
    assert len(creds.transforms_for("uploads.github.com")) == 1


def test_multiple_bindings_different_hosts():
    creds = config.load_resolved({"bindings": [
        _entry(name="gh", hosts=["api.github.com"], placeholder="ph1"),
        _entry(name="ex", hosts=["api.example.com"], placeholder="ph2",
               params={"header": "X-API-Key"}),
    ]})
    assert creds.intercept_hosts() == {"api.github.com", "api.example.com"}
    [t1] = creds.transforms_for("api.github.com")
    assert t1.placeholder == "ph1"
    [t2] = creds.transforms_for("api.example.com")
    assert t2.placeholder == "ph2"


def test_same_host_different_headers_allowed():
    """Two bindings on the same host with different headers is valid."""
    creds = config.load_resolved({"bindings": [
        _entry(name="b1", placeholder="ph1", params={"header": "Authorization"}),
        _entry(name="b2", placeholder="ph2", params={"header": "X-Extra-Token"}),
    ]})
    ts = creds.transforms_for("api.github.com")
    assert len(ts) == 2
    headers = {t.params["header"] for t in ts}
    assert headers == {"Authorization", "X-Extra-Token"}


def test_body_scheme_needs_no_header():
    """A body-scheme binding validates without a header param."""
    creds = config.load_resolved({"bindings": [
        _entry(scheme="body", params={}, placeholder="ph")
    ]})
    [t] = creds.transforms_for("api.github.com")
    assert t.scheme.name == "body"


def test_sign_scheme_multi_slot_no_placeholder():
    """A sigv4 (sign-family) binding validates with two secret slots and no
    placeholder."""
    creds = config.load_resolved({"bindings": [{
        "name": "aws", "hosts": ["sts.amazonaws.com"], "scheme": "sigv4",
        "secret": {"access_key_id": "AKID", "secret_access_key": "SAK"},
    }]})
    [t] = creds.transforms_for("sts.amazonaws.com")
    assert t.scheme.name == "sigv4"
    assert t.placeholder is None
    assert t.secrets == {"access_key_id": "AKID", "secret_access_key": "SAK"}


def test_transforms_for_unknown_host_returns_empty():
    creds = config.load_resolved({"bindings": [_entry()]})
    assert creds.transforms_for("not-configured.com") == []


def test_empty_bindings_no_intercepts():
    creds = config.load_resolved({"bindings": []})
    assert creds.intercept_hosts() == set()
    assert creds.transforms_for("anything.example") == []
    assert creds.inward_bindings() == []


def test_binding_credentials_empty_default():
    creds = config.BindingCredentials({})
    assert creds.intercept_hosts() == set()
    assert creds.transforms_for("anything.example") == []
    assert creds.inward_bindings() == []


def test_inward_bindings_excludes_secret():
    """inward_bindings() must not expose the real credential value."""
    creds = config.load_resolved({"bindings": [
        _entry(secret={"value": "super_secret_value"}, env="GH_TOKEN")
    ]})
    [ib] = creds.inward_bindings()
    assert ib.name == "b"
    assert ib.placeholder == "ph"
    assert ib.env == "GH_TOKEN"
    assert ib.scheme == "bearer"
    assert ib.params == {"header": "Authorization"}
    assert ib.hosts == ["api.github.com"]
    # No secret/real anywhere on the inward descriptor.
    assert not hasattr(ib, "real")
    assert not hasattr(ib, "secret")


# ---- glob host patterns ----

def _sigv4(**over):
    e = {
        "name": "aws", "hosts": ["*.amazonaws.com"], "scheme": "sigv4",
        "secret": {"access_key_id": "AKID", "secret_access_key": "SAK"},
    }
    e.update(over)
    return e


def test_pattern_transforms_match_across_regions():
    """A single `*.amazonaws.com` sigv4 binding covers every regional host."""
    creds = config.load_resolved({"bindings": [_sigv4()]})
    for host in ("s3.us-east-1.amazonaws.com", "dynamodb.eu-west-1.amazonaws.com"):
        [t] = creds.transforms_for(host)
        assert t.scheme.name == "sigv4"


def test_pattern_does_not_match_other_domains():
    creds = config.load_resolved({"bindings": [_sigv4()]})
    assert creds.transforms_for("api.github.com") == []
    assert creds.transforms_for("amazonaws.com.evil.test") == []


def test_intercepts_predicate_literal_and_pattern():
    creds = config.load_resolved({"bindings": [
        _entry(name="gh", hosts=["api.github.com"]),
        _sigv4(),
    ]})
    assert creds.intercepts("api.github.com") is True          # literal
    assert creds.intercepts("s3.us-east-1.amazonaws.com") is True  # pattern
    assert creds.intercepts("example.com") is False
    assert creds.intercepts(None) is False
    assert creds.intercepts("") is False


def test_intercept_hosts_enumerates_pattern_strings():
    """intercept_hosts() can't enumerate matched SNIs, so it surfaces the
    pattern string itself (for /setup disclosure + logging)."""
    creds = config.load_resolved({"bindings": [
        _entry(name="gh", hosts=["api.github.com"]),
        _sigv4(),
    ]})
    assert creds.intercept_hosts() == {"api.github.com", "*.amazonaws.com"}


def test_scoped_pattern_only_matches_its_service():
    creds = config.load_resolved({"bindings": [_sigv4(hosts=["s3.*.amazonaws.com"])]})
    assert len(creds.transforms_for("s3.us-east-1.amazonaws.com")) == 1
    assert creds.transforms_for("dynamodb.us-east-1.amazonaws.com") == []


def test_literal_and_pattern_both_apply_literal_first():
    """A host matched by both a literal binding and a pattern binding gets both
    transforms, literals (most specific) before patterns."""
    creds = config.load_resolved({"bindings": [
        _entry(name="exact", hosts=["s3.us-east-1.amazonaws.com"],
               params={"header": "X-Extra"}, placeholder="ph"),
        _sigv4(),
    ]})
    ts = creds.transforms_for("s3.us-east-1.amazonaws.com")
    assert [t.name for t in ts] == ["exact", "aws"]


def test_reject_overbroad_pattern():
    with pytest.raises(config.ConfigError, match="too broad"):
        config.load_resolved({"bindings": [_sigv4(hosts=["*.com"])]})


def test_reject_wildcard_in_registrable_domain():
    with pytest.raises(config.ConfigError, match="registrable domain"):
        config.load_resolved({"bindings": [_sigv4(hosts=["a.*.com"])]})


def test_reject_bare_star_pattern():
    with pytest.raises(config.ConfigError, match="too broad"):
        config.load_resolved({"bindings": [_sigv4(hosts=["*"])]})


def test_duplicate_identical_pattern_same_location_rejected():
    """Two bindings sharing an identical pattern + wire location still collide
    (the uniqueness check keys on the host string, pattern or literal)."""
    with pytest.raises(config.ConfigError, match="both write"):
        config.load_resolved({"bindings": [
            _entry(name="a", hosts=["*.example.com"], placeholder="p1"),
            _entry(name="b", hosts=["*.example.com"], placeholder="p1"),
        ]})
