"""Host-pattern validation, mirrored from the proxy's proxy/hostmatch.py.

A binding's `hosts` entry is either a literal hostname or a glob pattern
containing `*` (`*.amazonaws.com` scopes a binding to every AWS region/service
endpoint). The proxy compiles and matches patterns at request time; the CLI
only needs to *validate* them, so a bad pattern is rejected at `binding add`
rather than only when the proxy validates the pushed config. Keep the rules
here in sync with proxy/hostmatch.py.
"""
from __future__ import annotations


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
