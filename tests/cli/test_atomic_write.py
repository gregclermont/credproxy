"""atomic_write_text: torn-write safety for the source-of-truth / state files
(workspace TOML, applied-spec/-bindings, setup_done, the default pointer)."""
from __future__ import annotations

import os

import pytest

from credproxy_cli.core.paths import atomic_write_text


def test_creates_file_and_leaves_no_tmp(tmp_path):
    p = tmp_path / "x.json"
    atomic_write_text(p, '{"a":1}')
    assert p.read_text() == '{"a":1}'
    assert list(tmp_path.iterdir()) == [p]            # no .tmp litter left behind


def test_makes_missing_parent_dirs(tmp_path):
    p = tmp_path / "state" / "ws" / "applied-spec.json"
    atomic_write_text(p, "{}")
    assert p.read_text() == "{}"


def test_overwrite_preserves_existing_mode(tmp_path):
    p = tmp_path / "auth"
    p.write_text("old")
    os.chmod(p, 0o600)
    atomic_write_text(p, "new")
    assert p.read_text() == "new"
    assert (p.stat().st_mode & 0o777) == 0o600        # not reset to umask default


def test_failed_replace_preserves_original_and_cleans_tmp(tmp_path, monkeypatch):
    """A write that dies at the rename must leave the ORIGINAL intact (never a
    truncated/blank file) and not litter a temp -- the whole point of the helper."""
    p = tmp_path / "default-workspace"
    p.write_text("ORIGINAL\n")

    def boom(src, dst):
        raise OSError("simulated crash during rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        atomic_write_text(p, "NEW\n")

    assert p.read_text() == "ORIGINAL\n"              # old contents survive
    assert list(tmp_path.iterdir()) == [p]            # temp cleaned up
