"""Proxy-side placeholder generator (the re-seal mint seam).

A re-seal scheme mints a placeholder at response time for a runtime-derived
secret, exactly as the CLI generates one at authoring time. The pattern
(prefix/length/charset) is duplicated here rather than shared because the proxy
must not import the host CLI -- the two stay separated (CLAUDE.md). Keep this in
sync with cli/credproxy_cli/core/injectors.py if the charset vocabulary grows.
"""
from __future__ import annotations

import secrets
import string

_CHARSETS = {
    "alnumeric": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
}

DEFAULT_PREFIX = "credproxy_"
DEFAULT_LENGTH = 40
DEFAULT_CHARSET = "alnumeric"


def generate(prefix: str = DEFAULT_PREFIX, length: int = DEFAULT_LENGTH,
             charset: str = DEFAULT_CHARSET) -> str:
    """One format-valid sentinel: `prefix` then random `charset` chars to
    `length`, drawn from `secrets`."""
    alphabet = _CHARSETS[charset]
    n = max(0, length - len(prefix))
    return prefix + "".join(secrets.choice(alphabet) for _ in range(n))
