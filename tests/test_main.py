"""Tests for proxy/main.py — _load_secrets stdin parser."""
import io
import sys

import pytest

import main


def feed(monkeypatch, text: str):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def test_empty_stdin_returns_empty_dict(monkeypatch):
    feed(monkeypatch, "")
    assert main._load_secrets() == {}


def test_whitespace_only_returns_empty_dict(monkeypatch):
    feed(monkeypatch, "\n\n  \n")
    assert main._load_secrets() == {}


def test_valid_json_object(monkeypatch):
    feed(monkeypatch, '{"FOO": "bar", "BAZ": "qux"}')
    assert main._load_secrets() == {"FOO": "bar", "BAZ": "qux"}


def test_multiline_value(monkeypatch):
    feed(monkeypatch, '{"PEM": "-----BEGIN-----\\nbody\\n-----END-----"}')
    assert main._load_secrets() == {"PEM": "-----BEGIN-----\nbody\n-----END-----"}


def test_invalid_json_exits(monkeypatch):
    feed(monkeypatch, "not json")
    with pytest.raises(SystemExit, match="invalid JSON"):
        main._load_secrets()


def test_non_object_root_exits(monkeypatch):
    feed(monkeypatch, "[1, 2, 3]")
    with pytest.raises(SystemExit, match="must be an object"):
        main._load_secrets()


def test_non_string_value_exits(monkeypatch):
    feed(monkeypatch, '{"FOO": 42}')
    with pytest.raises(SystemExit, match="must be a string"):
        main._load_secrets()


def test_null_value_exits(monkeypatch):
    feed(monkeypatch, '{"FOO": null}')
    with pytest.raises(SystemExit, match="must be a string"):
        main._load_secrets()


def test_empty_key_exits(monkeypatch):
    feed(monkeypatch, '{"": "x"}')
    with pytest.raises(SystemExit, match="non-empty"):
        main._load_secrets()
