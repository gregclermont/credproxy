"""The builtin macOS `keychain` provider.

It shells out to the `security` CLI, which only exists on macOS, so these tests
run it against a fake `security` placed on PATH -- exercising the request
parsing, response shape, newline handling, and exit codes without a real
Keychain.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest


def _keychain():
    from credproxy_cli.core.paths import builtin_providers_dir
    return builtin_providers_dir() / "keychain"


@pytest.fixture
def fake_security(tmp_path, monkeypatch):
    """A stub `security` on PATH: returns 'topsecret\\n' for service 'good',
    fails otherwise (mimicking `security find-generic-password -s X -w`)."""
    sec = tmp_path / "security"
    sec.write_text(
        "#!/bin/sh\n"
        'svc=""\n'
        'while [ $# -gt 0 ]; do case "$1" in -s) svc="$2"; shift 2;; *) shift;; esac; done\n'
        '[ "$svc" = "good" ] && { printf \'topsecret\\n\'; exit 0; }\n'
        "exit 44\n"
    )
    sec.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    return sec


def _run(req: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_keychain())], input=json.dumps(req),
        capture_output=True, text=True,
    )


def test_keychain_found(fake_security):
    r = _run({"version": 1, "op": "get", "secrets": ["good"]})
    assert r.returncode == 0
    # The single trailing newline from `-w` is stripped; the value is exact.
    assert json.loads(r.stdout) == {"values": {"good": "topsecret"}}


def test_keychain_multiple(fake_security):
    # Two refs, one missing -> first miss fails the whole batch (exit 2).
    r = _run({"version": 1, "op": "get", "secrets": ["good", "nope"]})
    assert r.returncode == 2


def test_keychain_missing_binary_exits_1(tmp_path, monkeypatch):
    """When `security` isn't on PATH, the provider exits 1 cleanly, not a
    traceback. (Run via the interpreter so PATH can be emptied.)"""
    import sys
    monkeypatch.setenv("PATH", str(tmp_path))          # no `security` on PATH
    r = subprocess.run(
        [sys.executable, str(_keychain())],
        input=json.dumps({"version": 1, "op": "get", "secrets": ["good"]}),
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "not on PATH" in r.stderr
    assert "Traceback" not in r.stderr


def test_keychain_not_found(fake_security):
    r = _run({"version": 1, "op": "get", "secrets": ["nope"]})
    assert r.returncode == 2
    assert "no generic-password item" in r.stderr
    assert "add-generic-password" in r.stderr  # tells the user how to store it


def test_keychain_unsupported_version(fake_security):
    r = _run({"version": 2, "op": "get", "secrets": []})
    assert r.returncode == 3


def test_keychain_is_executable():
    assert os.access(_keychain(), os.X_OK)
