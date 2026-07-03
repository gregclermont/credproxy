"""Structured, tagged audit stream for the proxy's own governance decisions.

The proxy holds real credentials and injects them (and, with the rules layer,
governs traffic) on behalf of a semi-trusted workspace. "Which credential was
used, when, against which host" and "which policy rule fired" are first-class
questions the ephemeral `[http] ... (inject:name)` debug line can't answer
durably. This module emits a second, machine-parseable stream for exactly those
events.

Transport is option (b) of #24: tagged JSON-lines on **stdout** (`[audit] {json}`),
so `docker logs` is the store -- rotation and persistence-across-restart come for
free from Docker's log driver (persists across stop/start, not across `rm`). The
host CLI filters the stream with `logs --audit`. A dedicated file/volume sink is
a possible follow-up; the event shape here does not change if the sink does.

Safe-by-construction: an event is a flat dict of small structural fields
(binding/rule NAMES, host, method, query-stripped path, a coarse outcome). It
NEVER carries a secret value, a header value, a placeholder's real substitution,
or a script's source. `emit()` takes only the caller's chosen fields; there is no
path by which a credential reaches this stream. The `[http]` human line is left
untouched -- this is an additive stream, so existing debugging habits keep
working.
"""
from __future__ import annotations

import json
import time

# The tag every audit line carries, so `docker logs` can be filtered to the
# audit stream (CLI `logs --audit`) and so a human scanning the log can tell an
# audit event from ordinary `[http]`/`[sni]`/`[scheme]` debug output.
TAG = "[audit]"


def emit(event: str, **fields) -> None:
    """Print one audit event as a tagged JSON line to stdout.

    `event` names the kind (`inject`, `no-inject`, `reseal`, `rule`); `fields`
    are the event-specific structural facts. A `ts` (RFC 3339 UTC, second
    precision) is stamped here so every event is self-dating even when the
    container log driver adds no timestamp. Callers must pass only non-secret
    structural values -- see the module docstring."""
    record = {"ts": _now_iso(), "event": event}
    # Drop None-valued fields so an absent method/path doesn't clutter the line;
    # a consumer treats a missing key as "not applicable".
    record.update({k: v for k, v in fields.items() if v is not None})
    # Compact, single line (JSON-lines): one event per `docker logs` line.
    print(f"{TAG} {json.dumps(record, separators=(',', ':'))}", flush=True)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
