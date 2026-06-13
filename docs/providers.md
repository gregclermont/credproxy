# Provider exec protocol

A **provider** is a host-side executable that fetches a secret value from a
backend (a vault, an environment variable, the OS keychain, a script). The CLI
execs it at `start` / `config push` / `binding test` time and pushes the
**resolved value** to the proxy. Because it is just an executable speaking a
tiny line protocol, a provider can be written in anything — a one-line bash
wrapper around `op`/`vault`, or a compiled binary — and can use whatever host
tooling it needs.

The protocol is intentionally small and **versioned** so it can grow without
breaking existing providers. The spawning parent is **not** part of the
contract: today the CLI execs the provider, but a future daemon may take that
role. A provider must not assume who its parent is.

## Discovery

A provider is referenced by `<name>`. Lookup order (first match wins, so a
user definition shadows a bundled one of the same name):

1. `$XDG_CONFIG_HOME/credproxy/providers/<name>` — either an executable file,
   or a directory containing an executable `run`.
2. Bundled with the tool at `cli/credproxy_cli/bundled/providers/<name>` (same
   two shapes).

## Request (stdin)

A single JSON object on stdin:

```json
{"version": 1, "op": "get", "secret": "<opaque provider-interpreted ref>"}
```

- `version` — protocol version. Currently `1`. A provider that does not
  understand the version must exit `3`.
- `op` — the operation. Currently only `get` (fetch one secret by id). The
  field exists so future operations (`list`, `describe`, …) can be added; an
  unknown `op` must exit `3`.
- `secret` — the opaque secret reference, interpreted entirely by the provider
  (a vault path, an env-var name, an item ref, …). credproxy never parses it.

## Response (stdout)

On success, **stdout must contain nothing but** a single JSON object, and the
process must exit `0`:

```json
{"value": "<secret>"}
```

Anything else on stdout (banners, debug logging, prompts) corrupts the
response — see the note on interactive tools below.

## Failure

On failure, exit **nonzero** and write human-readable diagnostics to
**stderr**. stderr stays inherited from the terminal, so a provider that wraps
an interactive vault CLI can prompt the user there. The CLI does **not** capture
stderr — anything written there goes directly to the terminal and is not
included in the CLI's error message (which reports only the exit code and the
secret reference).

### Exit codes

| code | meaning |
|------|---------|
| `0`  | success; a `{"value": ...}` object is on stdout |
| `1`  | generic failure (backend unreachable, auth error, malformed request, …) |
| `2`  | secret not found (the `secret` ref does not resolve) |
| `3`  | unsupported `op` or `version` |

The CLI maps `2` and `3` to specific diagnostics; any other nonzero code is a
generic provider failure.

## Interactive providers

Because stdout is reserved for the response JSON and stderr stays attached to
the terminal, an interactive tool (a vault CLI that prompts for a passphrase,
an MFA tap) **must** prompt via **stderr** or `/dev/tty`, never stdout. Writing
a prompt to stdout would be parsed as part of the response and fail.

The CLI uses a generous timeout (120s) precisely so an interactive prompt has
time to be answered.

## Example: the bundled `env` provider

The simplest possible provider reads a host environment variable named by the
`secret` ref:

```sh
#!/bin/sh
# Request JSON on stdin: {"version":1,"op":"get","secret":"GITHUB_TOKEN"}
# Emits {"value":"<$GITHUB_TOKEN>"} on stdout, or exits 2 if unset.
# NB: use `python3 -c`, not a `<<HEREDOC` -- a heredoc would consume the
# stdin the request is delivered on.
exec python3 -c '
import json, os, sys
req = json.load(sys.stdin)
if req.get("version") != 1 or req.get("op") != "get":
    sys.exit(3)
name = req.get("secret") or ""
val = os.environ.get(name)
if val is None:
    print(f"env provider: ${name} is not set", file=sys.stderr)
    sys.exit(2)
json.dump({"value": val}, sys.stdout)
'
```
