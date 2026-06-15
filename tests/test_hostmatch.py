"""Tests for proxy/hostmatch.py — literal vs. glob classification, strict
pattern validation, and glob->regex compilation."""
import hostmatch


# ---- is_pattern ----

def test_literal_is_not_pattern():
    assert hostmatch.is_pattern("api.github.com") is False


def test_star_is_pattern():
    assert hostmatch.is_pattern("*.amazonaws.com") is True
    assert hostmatch.is_pattern("s3.*.amazonaws.com") is True


# ---- validate_pattern: accepted ----

def test_valid_leading_wildcard():
    assert hostmatch.validate_pattern("*.amazonaws.com") is None


def test_valid_mid_wildcard():
    assert hostmatch.validate_pattern("s3.*.amazonaws.com") is None


def test_valid_partial_label_wildcard():
    # `*` inside a non-trailing label is fine.
    assert hostmatch.validate_pattern("s3-*.us-east-1.amazonaws.com") is None


# ---- validate_pattern: rejected (strict guardrails) ----

def test_reject_bare_star():
    assert "too broad" in hostmatch.validate_pattern("*")


def test_reject_tld_wildcard():
    # `*.com` (only two labels) would target a whole TLD.
    assert "too broad" in hostmatch.validate_pattern("*.com")


def test_reject_all_wildcard():
    assert hostmatch.validate_pattern("*.*") is not None


def test_reject_wildcard_in_second_label():
    # `a.*.com` leaves only the TLD literal.
    assert "registrable domain" in hostmatch.validate_pattern("a.*.com")


def test_reject_empty_label():
    assert "empty label" in hostmatch.validate_pattern("*..amazonaws.com")


# ---- compile_pattern: matching semantics ----

def test_star_matches_across_dots():
    rx = hostmatch.compile_pattern("*.amazonaws.com")
    assert rx.fullmatch("s3.us-east-1.amazonaws.com")
    assert rx.fullmatch("dynamodb.eu-west-1.amazonaws.com")


def test_scoped_pattern_matches_only_its_service():
    rx = hostmatch.compile_pattern("s3.*.amazonaws.com")
    assert rx.fullmatch("s3.us-east-1.amazonaws.com")
    assert not rx.fullmatch("dynamodb.us-east-1.amazonaws.com")


def test_pattern_requires_the_literal_suffix():
    rx = hostmatch.compile_pattern("*.amazonaws.com")
    assert not rx.fullmatch("s3.us-east-1.amazonaws.com.evil.test")
    # apex without the leading subdomain doesn't match a `*.`-anchored pattern.
    assert not rx.fullmatch("amazonaws.com")


def test_pattern_is_case_insensitive():
    rx = hostmatch.compile_pattern("*.amazonaws.com")
    assert rx.fullmatch("S3.US-EAST-1.AMAZONAWS.COM")


def test_dot_is_literal_not_wildcard():
    rx = hostmatch.compile_pattern("*.amazonaws.com")
    # the dots are escaped, so a different char where a dot is expected fails.
    assert not rx.fullmatch("s3-amazonaws-com")
