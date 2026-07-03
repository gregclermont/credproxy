"""Path globbing for rule scoping -- the CLI mirror of proxy/rules.py.

A rule's optional `path` is a segment-aware glob: `*` matches within one path
segment, `**` crosses segments (`/repos/**` covers `/repos/a/b`). This module is
kept BYTE-PARITY with `proxy/rules.py`'s `path_to_regex`/`validate_path` so
`rule test` on the host agrees with the proxy's matcher; the parity is guarded by
tests/cli/test_wire_parity.py (the hostmatch precedent).
"""
from __future__ import annotations

import re


def path_to_regex(glob: str) -> str:
    r"""Translate a path glob to an anchored regex string. `**` -> `.*` (crosses
    `/`); `*` -> `[^/]*` (within one segment); every other character literal.
    MUST match proxy/rules.py.path_to_regex exactly."""
    out: list[str] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "^" + "".join(out) + "$"


def validate_path(glob: str) -> str | None:
    """Return an error message if `glob` is an unusable path pattern, else None.
    Mirrors proxy/rules.py.validate_path."""
    if not glob:
        return "path must be a non-empty string"
    if not glob.startswith("/"):
        return f"path '{glob}' must start with '/'"
    return None


def compile_path(glob: str) -> re.Pattern:
    """Compile a validated path glob to a full-match regex."""
    return re.compile(path_to_regex(glob))
