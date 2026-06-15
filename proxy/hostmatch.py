"""Hostname matching for binding scoping: exact literals + glob patterns.

A binding's `hosts` entries are either literal hostnames (exact match -- the
fast dict path in config.py) or glob patterns. A pattern is any entry
containing `*`; the `*` matches any run of characters **including dots**, so
`*.amazonaws.com` covers every AWS region/service endpoint and
`s3.*.amazonaws.com` scopes to S3 across regions. This is what lets one binding
span AWS regional endpoints: the sigv4 scheme reads region+service from the
request, so a single binding re-signs them all.

Patterns are validated strictly (`validate_pattern`): the two rightmost labels
must be present and literal, so the registrable domain is always pinned and an
over-broad pattern (`*`, `*.com`, `*.*`) can't smuggle a real credential onto
an attacker-chosen host. This module is mirrored on the host side by the CLI's
binding validation (`core/hostmatch.py`) so a bad pattern is rejected at
`binding add`, not only when the proxy validates the pushed config.
"""
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
    """Compile a glob pattern to a full-match, case-insensitive regex. `*` ->
    `.*` (matches across label boundaries); every other character is literal.
    Assumes `host` already passed `validate_pattern`."""
    rx = re.escape(host).replace(r"\*", ".*")
    return re.compile(rx, re.IGNORECASE)
