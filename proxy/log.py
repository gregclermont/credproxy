"""Structured, prefixed log stream for the proxy's own output.

Every proxy-authored line is `credproxy {json}` -- one JSON object per line with a
`kind` and an RFC-3339 `ts`. Two payoffs:

- **Uniform + machine-parseable.** The host CLI's `logs` reads this stream and
  reformats it (`logs --json` passes the raw records through; `logs --audit`
  filters `kind == "audit"`). mitmproxy's own termlog is left untouched -- the CLI
  passes any non-`credproxy` line through verbatim.
- **Safe by construction.** Untrusted content -- a rule/scheme error message that
  can echo workspace input -- is always a JSON-encoded VALUE, so its newlines are
  escaped and it can never spill a forged record onto its own line. (Contrast a
  raw text log, where a rule script `fail('...\\n[audit] {..}')` could forge an
  audit event on the next physical line.)

Audit events (`kind == "audit"`, with an `event` subfield: `inject`, `no-inject`,
`reseal`, `rule`) carry ONLY structural facts -- binding/rule names, host, method,
query-stripped path, a coarse outcome -- NEVER a secret value or a header value.
Human/debug kinds: `http`, `api`, `sni`, `scheme`, `script`, `rule-error`,
`sigv4`, `main`.
"""
from __future__ import annotations

import json
import time

# Prefix on every proxy-authored line, so a bare `docker logs` is greppable and
# the CLI can tell our structured records from mitmproxy's raw termlog.
PREFIX = "credproxy "


def emit(kind: str, **fields) -> None:
    """Print one structured record: `credproxy {json}` with `kind` + `ts` + the
    given fields (None-valued fields dropped). Untrusted values (error strings)
    are JSON-encoded here, so they can never break out onto their own line."""
    record = {"ts": _now_iso(), "kind": kind}
    record.update({k: v for k, v in fields.items() if v is not None})
    print(f"{PREFIX}{json.dumps(record, separators=(',', ':'))}", flush=True)


def audit(event: str, **fields) -> None:
    """A governance audit event (`kind == "audit"`). Structural facts only."""
    emit("audit", event=event, **fields)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
