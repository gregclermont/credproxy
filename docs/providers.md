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

Scaffold a starting point with `credproxy provider scaffold NAME` (Python) or
`credproxy provider scaffold NAME --lang sh` (POSIX shell + `jq`). Both emit the
same protocol in the same shape — a metadata block (`NAME`/`DESCRIPTION`/`HELP`/
version), a `fetch`/`get` function to fill in for your backend, and an identical
protocol footer — so they diff cleanly and the language choice is yours.

## Discovery

A provider is referenced by `<name>`. Lookup order (first match wins, so a
user definition shadows a bundled one of the same name):

1. `$XDG_CONFIG_HOME/credproxy/providers/<name>` — either an executable file,
   or a directory containing an executable `run`.
2. Bundled with the tool at `cli/credproxy_cli/bundled/providers/<name>` (same
   two shapes).

## Request (stdin)

A single JSON object on stdin. The protocol is **batch-native**: one invocation
carries a list of refs. The CLI batches **across bindings**, not just within one
— at resolve time (`start` / `apply` / `binding test`) it groups every binding's
refs by provider and invokes each provider **once** with the deduped union. So a
provider's setup cost is paid once per resolve, not once per binding: an
interactive provider prompts **once** for the whole workspace, and a vault that
must unlock unlocks **once** however many bindings draw from it.

```json
{"version": 1, "op": "get", "secrets": ["<ref>", "<ref>", ...]}
```

- `version` — protocol version. Currently `1`. A provider that does not
  understand the version must exit `3`.
- `op` — the operation: `get` (fetch the listed secrets), `describe` (a one-line
  description), or `help` (longer usage text). See "Describe and help" below.
  An unknown `op` must exit `3`.
- `secrets` — a list of opaque secret references, each interpreted entirely by
  the provider (a vault path, an env-var name, an item ref, …). credproxy never
  parses them. A single value is just a list of one.

## Response (stdout)

On success, **stdout must contain nothing but** a single JSON object mapping
**every requested ref** to its value, and the process must exit `0`:

```json
{"values": {"<ref>": "<secret>", ...}}
```

Every ref in the request must appear in `values` as a string, or the CLI treats
it as a protocol error. Anything else on stdout (banners, debug logging,
prompts) corrupts the response — see the note on interactive tools below.

## Describe and help (optional)

Two metadata ops let a provider document itself. Both **run the provider**, so
each must be cheap and side-effect-free — return the text without touching the
backend (the bundled `keychain`/`op` providers answer them *before* invoking
`security`/`op`, so listing/showing never triggers a Keychain prompt or a
1Password unlock). A provider that doesn't implement an op simply exits `3` and
the field is omitted, so older providers keep working. Neither is ever called on
the fetch path.

- **`describe`** — `credproxy provider list` runs each provider with
  `{"version": 1, "op": "describe"}`; the provider returns a one-line summary:

  ```json
  {"description": "1Password (op CLI)"}
  ```

- **`help`** — `credproxy provider show NAME` runs the provider with
  `{"version": 1, "op": "help"}`; the provider returns longer usage text (ref
  format, prerequisites, an example):

  ```json
  {"help": "Reads secrets from 1Password (op CLI).\n  ref: op://<vault>/<item>/<field>\n  ..."}
  ```

  `provider show` also prints the provider's source and resolved path.

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
| `0`  | success; a `{"values": {...}}` object covering every requested ref is on stdout |
| `1`  | generic failure (backend unreachable, auth error, malformed request, …) |
| `2`  | secret not found (a requested ref does not resolve) |
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

The bundled `bw` (Bitwarden) provider is the canonical example: it reuses
`$BW_SESSION` when the vault is already unlocked, and otherwise prompts for the
master password on the terminal. Because the CLI batches every binding on a
provider into one invocation and `bw` reads the whole vault in a single
`bw list items`, that prompt (and the decrypt behind it) happens **once** per
resolve no matter how many bindings draw from the vault.

A provider that wraps an already-authenticated session need not be interactive
at all: the bundled `gh-cli` provider returns `gh auth token --hostname <ref>`
(ref = a GitHub hostname; empty = gh's default host), reading gh's own keyring
without prompting. Its `describe`/`help` are static — like every provider, the
backend is touched only in the `get` path, so `provider list`/`show` never
shells out. It pairs with the `github` preset, which defaults its provider to
`gh-cli` and its secret to `github.com`, so `binding add --preset github` wires
GitHub API + git + ghcr off one existing login with no further flags.

The bundled `docker-credential` provider adapts any `docker-credential-*` helper
for registry auth: the ref is a registry host (the helper is resolved from
`${DOCKER_CONFIG:-~/.docker}/config.json` — `credHelpers[host]`, else
`credsStore`) or an explicit `<helper>|<host>`. It returns the helper's `Secret`
and pairs with the `basic` scheme. **Caveat:** `basic` swaps the password
component by position, so the **username is not injected** — the workspace must
send the username the registry expects (e.g. `AWS` for ECR) with the placeholder
in the password slot. It covers only the credential-*helper* mechanism, not the
static base64 `auths` a plain `docker login` may write. The helper protocol is
per-host, so unlike `bw`'s one-unlock-per-resolve a vault-backed helper prompts
once per distinct host; the config is still read once per invocation and
identical `(helper, host)` refs are de-duped.

## Example: the bundled `env` provider

The simplest possible provider reads host environment variables named by the
request's `secrets` refs:

```sh
#!/bin/sh
# Request JSON on stdin: {"version":1,"op":"get","secrets":["GITHUB_TOKEN",...]}
# Emits {"values":{"GITHUB_TOKEN":"<$GITHUB_TOKEN>",...}}, or exits 2 if any
# var is unset.
# NB: use `python3 -c`, not a `<<HEREDOC` -- a heredoc would consume the
# stdin the request is delivered on.
exec python3 -c '
import json, os, sys
req = json.load(sys.stdin)
if req.get("version") != 1 or req.get("op") != "get":
    sys.exit(3)
values = {}
for name in req.get("secrets") or []:
    val = os.environ.get(name)
    if val is None:
        print(f"env provider: ${name} is not set", file=sys.stderr)
        sys.exit(2)
    values[name] = val
json.dump({"values": values}, sys.stdout)
'
```
