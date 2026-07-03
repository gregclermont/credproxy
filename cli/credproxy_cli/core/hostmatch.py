"""Host-pattern validation + compilation, mirrored from proxy/hostmatch.py.

A binding's `hosts` entry is either a literal hostname or a glob pattern
containing `*` (`*.amazonaws.com` scopes a binding to every AWS region/service
endpoint). Bindings only need to *validate* a pattern on the CLI (matching
happens in the proxy at request time), but `rule test` DOES match host globs on
the host to answer "which rule fires?", so `compile_pattern` is mirrored too.
Keep the rules here in sync with proxy/hostmatch.py.
"""
from __future__ import annotations

import re


def is_pattern(host: str) -> bool:
    """True if `host` is a glob pattern (contains `*`) rather than a literal."""
    return "*" in host


def validate_pattern(host: str) -> str | None:
    """Return an error message if `host` is an invalid glob pattern, else None.

    Strict rules (this decides where a real credential is injected): a pattern
    must have at least three dot-separated labels, no empty labels, and the two
    rightmost labels must be literal (no `*`). Allows `*.amazonaws.com` and
    `s3.*.amazonaws.com`; rejects `*`, `*.com`, `*.*`, and `a.*.com`. Call only
    on strings for which `is_pattern` is true."""
    labels = host.split(".")
    if any(lbl == "" for lbl in labels):
        return f"host pattern '{host}' has an empty label"
    if len(labels) < 3:
        return (
            f"host pattern '{host}' is too broad: a pattern needs a wildcard "
            f"label plus at least two literal trailing labels "
            f"(e.g. '*.example.com')"
        )
    if "*" in labels[-1] or "*" in labels[-2]:
        return (
            f"host pattern '{host}' must pin a literal registrable domain: the "
            f"two rightmost labels can't contain '*' (e.g. '*.example.com', not "
            f"'*.com')"
        )
    return None


def compile_pattern(host: str) -> re.Pattern:
    """Compile a glob pattern to a full-match, case-insensitive regex (mirrors
    proxy/hostmatch.py.compile_pattern). `*` -> `.*`; every other char literal.
    Assumes `host` already passed `validate_pattern`."""
    rx = re.escape(host).replace(r"\*", ".*")
    return re.compile(rx, re.IGNORECASE)
