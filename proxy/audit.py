"""Governance audit events -- a thin alias over the structured log.

`audit.emit(event, **fields)` records one `kind == "audit"` record (see log.py):
credential injection, re-seal mint, and every rule hit (visible or hidden). Kept
as its own name because the call sites read as governance ("emit an audit event"),
but the transport, framing, and forgery-resistance all live in `log`.
"""
from __future__ import annotations

import log

# audit.emit("inject", ...) -> log.audit("inject", ...) -> a kind="audit" record.
emit = log.audit
