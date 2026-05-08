"""Tests for proxy/main.py — _load_auth_token stdin envelope parser."""
import io
import sys

import pytest

import main


def feed(monkeypatch, text: str):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


# ---- Happy paths ----

def test_minimal_envelope(monkeypatch):
    feed(monkeypatch, '{"auth_token": "abc"}')
    assert main._load_auth_token() == "abc"


def test_envelope_ignores_extra_fields(monkeypatch):
    """Forward-compat: unknown fields shouldn't break startup."""
    feed(monkeypatch, '{"auth_token": "abc", "extra": "ignored"}')
    assert main._load_auth_token() == "abc"


# ---- Failure paths ----

def test_empty_stdin_exits(monkeypatch):
    feed(monkeypatch, "")
    with pytest.raises(SystemExit, match="empty stdin"):
        main._load_auth_token()


def test_whitespace_only_exits(monkeypatch):
    feed(monkeypatch, "\n\n  \n")
    with pytest.raises(SystemExit, match="empty stdin"):
        main._load_auth_token()


def test_invalid_json_exits(monkeypatch):
    feed(monkeypatch, "not json")
    with pytest.raises(SystemExit, match="invalid JSON"):
        main._load_auth_token()


def test_non_object_root_exits(monkeypatch):
    feed(monkeypatch, "[1, 2, 3]")
    with pytest.raises(SystemExit, match="must be an object"):
        main._load_auth_token()


def test_missing_auth_token_exits(monkeypatch):
    feed(monkeypatch, '{}')
    with pytest.raises(SystemExit, match="auth_token"):
        main._load_auth_token()


def test_empty_auth_token_exits(monkeypatch):
    feed(monkeypatch, '{"auth_token": ""}')
    with pytest.raises(SystemExit, match="auth_token"):
        main._load_auth_token()


def test_non_string_auth_token_exits(monkeypatch):
    feed(monkeypatch, '{"auth_token": 42}')
    with pytest.raises(SystemExit, match="auth_token"):
        main._load_auth_token()
