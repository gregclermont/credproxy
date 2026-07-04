# Rules — governing traffic on intercepted hosts

A **rule** is the credential-free sibling of a binding. Where a binding shapes a
credential *into* a request, a rule *governs* a request/response on an
intercepted host: block it, answer it with a stub, rewrite headers, or hand the
flow to a sandboxed Starlark script. Rules hold no secret, no provider, no
placeholder.

Rules exist for agent-sandbox-shaped needs:

- **Blast-radius control for real credentials** — allow `api.github.com`
  generally but block `DELETE /repos/**`; block `sts.amazonaws.com` so an AWS
  sigv4 binding can't mint temporary AssumeRole credentials into the workspace.
- **Stubbing / mocking** — pin `/v1/models` to a fixed body during tests.
- **Realistic failure injection / evals** — return a 429/500 *indistinguishable*
  from upstream (needs a hidden rule — an attributed fake contaminates the eval).
- **Tripwires** — silently block an endpoint the agent has no advertised reason
  to call, turning an attempt into a high-signal audit event.
- **Response scrubbing** — strip fields (emails, org metadata) from responses
  before the workspace sees them.

## The pipeline (a security invariant)

Rules run in a fixed order relative to credential injection:

```
request:   rules (declaration order) ──► injection schemes ──► upstream
response:  scheme on_response (re-seal) ──► response rules (declaration order)
```

Request rules run **before** injection: a blocked request never receives a
credential (and never logs as credential use), and a request rewrite happens
before sigv4 signs. Response rules run **after** re-seal: a token-endpoint
response is already sealed into a placeholder before any rule sees it.

**Consequence: rule code — declarative or script — never observes a real
credential.** It sees inert placeholders on the request side and exactly what the
workspace would see on the response side. Rules add no new exfiltration surface.

Evaluation is strict declaration order: `rewrite` actions apply cumulatively; the
first terminal action (`block`/`respond`, or a `script` that calls one)
short-circuits. A rule script that errors fails **closed** toward the policy —
the workspace gets `502 credproxy: rule 'NAME' failed`, never a proceed-un-governed.

## Interception is a union — a rule can flip a host to intercepted

Adding a rule to a host with no bindings makes that host TLS-terminated (it was
byte-passthrough before). A workspace that hasn't bootstrapped the proxy CA will
then see a **certificate error**, not a 403. Run the bootstrap first
(`curl -sSL http://proxy.local/bootstrap.sh | sh`).

This is *not* hostname egress allowlisting (a product non-goal): rules govern
HTTP on hosts you *name*; unnamed hosts stay passthrough, untouched and
unblockable. There is no deny-by-default mode — the hostmatch validation makes
"block everything except X" inexpressible (`*` / `*.com` are rejected).

## Config surface

Rules are a `[[rule]]` array in the workspace TOML, added via the CLI (below) or
by hand.

```toml
# Block repo deletion while allowing the rest of the GitHub API
[[rule]]
name    = "gh-no-delete"      # auto-generated if omitted
hosts   = ["api.github.com"]
methods = ["DELETE"]          # optional; absent = all methods
path    = "/repos/**"         # optional; * within a segment, ** across segments
action  = "block"             # 403 + self-identifying body (when visible)

# Close the AssumeRole hole while keeping sigv4 usable
[[rule]]
hosts  = ["sts.amazonaws.com", "sts.*.amazonaws.com"]
action = "block"

# Pin an endpoint to a stub
[[rule]]
hosts   = ["api.openai.com"]
path    = "/v1/models"
action  = "respond"
status  = 200
body    = '{"data": [{"id": "gpt-test"}]}'
headers = { "Content-Type" = "application/json" }

# Header-level rewrite (non-terminal; request + response headers)
[[rule]]
hosts          = ["api.example.com"]
action         = "rewrite"
set_headers    = { "X-Env" = "sandbox" }   # request
remove_headers = ["X-Request-Id"]          # request
# resp_set_headers / resp_remove_headers act on the response

# Arbitrary logic (hidden by default for script)
[[rule]]
hosts  = ["api.github.com"]
path   = "/users/**"
action = "script"
script = "scrub-emails"       # resolved via the three-tier scripts registry
```

### Matching

- `hosts` — literal or glob (`*.amazonaws.com`, `*` spans dots, host-only). The
  two rightmost labels must be literal.
- `methods` — optional list; absent = all.
- `path` — optional glob: `*` matches within one path segment, `**` crosses
  segments. `/repos/**` covers `/repos/a/b`; `/users/*/repos` does not match
  `/users/a/b/repos`.

### Actions

| action | terminal | params |
|---|---|---|
| `block` | yes | `status` (default 403) |
| `respond` | yes | `status` (required), `headers`, `body` |
| `rewrite` | no | request: `set_headers`, `remove_headers`; response: `resp_set_headers`, `resp_remove_headers` |
| `script` | either | `script` (registry name); terminal iff the script calls `block`/`respond` |

There is no query/body *matching* and no declarative body *rewrite* in v1 — the
`script` action covers those rare cases.

A rewrite cannot touch the request **authority**: setting or removing `Host` (or
`:authority`) is rejected — declaratively at `rule add`, and at runtime for a
scripted `req_set_header("Host", …)` (which fails closed with a 502). Binding
selection happens on the pre-rewrite host, so rewriting the authority would send
the injected credential under a different host than the binding is scoped to.
Scope is pinned by the host match, not mutable per request.

## Visibility (`visible`)

One per-rule flag bundles two disclosures:

- **Enumeration** — whether the rule appears in `/setup`'s `rules` array.
- **Attribution** — whether a hit self-identifies (an `X-Credproxy-Rule` header
  and, for a block, a `{"credproxy": {"blocked_by": "NAME"}}` body).

**Per-family defaults** (override with `visible = true/false`, or `--visible`/
`--hidden`):

- `block` / `respond` → **visible** (diagnosability; a disguised policy block
  sends a cooperative agent debugging its token).
- `rewrite` / response-side `script` → **hidden** (they emit no attribution
  anyway, and enumeration usually leaks the thing being hidden).

**Hidden behavior:** a hidden `block` is a bare status — no body, no marker. A
hidden `respond` is the exact counterfeit you authored (credproxy does not guess
at per-API mimicry: a convincing fake 404 is what `respond` is *for*).

**Invariant: hidden means hidden from the workspace, never from the operator.**
Proxy logs still print `(block:NAME)`; every hit is audited (hidden-rule hits are
arguably the *most* important to audit); `rule test` still reports matches; `rule
list` marks hidden rules `HIDDEN`.

### Two caveats

1. **Hiding is obscurity, not secrecy.** A workspace can infer a hidden rule by
   differential observation, and interception itself is detectable via the CA
   cert chain (adding a rule to a bindings-free host flips it to intercepted).
   Fine for cooperative-but-fallible agents; won't survive a determined
   adversary.
2. **A disguised block is deception with side effects.** An agent may act on a
   false premise (a counterfeit 404 → "the repo doesn't exist"). That's inherent
   and sometimes desired — it's why `visible = true` stays the terminal-action
   default.

## CLI

```
credproxy workspace NAME rule add ACTION --host HOST [scoping] [action params]
credproxy workspace NAME rule remove NAME
credproxy workspace NAME rule list
credproxy workspace NAME rule test METHOD URL
```

`ACTION` is a subcommand — `block`, `respond`, `rewrite`, or `script` — and each
owns exactly its own flags (e.g. `--body` is only valid under `respond`), so a
misplaced flag is rejected by the parser:

```
rule add block   --host api.github.com --method DELETE --path '/repos/**'
rule add respond --host api.openai.com --path /v1/models --status 200 --body '{}'
rule add rewrite --host api.example.com --header X-Env=sandbox --remove-header X-Id
rule add script  --host api.github.com --path '/users/**' --script scrub-emails
```

`rule test` is the dry-run evaluator — the primary "why was/wasn't this blocked?"
tool. It shares the host/method/path matcher with the proxy (wire-parity tested),
so for **declarative** rules (block/respond/rewrite) its answer is exactly what the
proxy will do. For **script** rules it's conservative: the host has no Starlark
runtime, so it can't tell a request-active script from a response-only one and
hedges every script as possibly-terminal (never hiding a later rule) — use
`--live` (below) for the authoritative per-script answer.

```
$ credproxy workspace myproj rule test DELETE https://api.github.com/repos/a/b
matched: gh-no-delete → block 403
$ credproxy workspace myproj rule test GET https://api.github.com/users/x
matched: scrub-emails → script:scrub-emails (may block/respond/rewrite)  [hidden]
```

(`rule test` runs on the host, which has no Starlark runtime, so it can't tell
whether a `script` rule acts in the request or response phase — it reports every
script as possibly-terminal (`may block/respond/rewrite`) and never stops at one,
so any rule listed after a script is annotated as conditional on that script not
terminating. `scrub-emails` is default-hidden, hence the `[hidden]` marker. The
proxy, which has the runtime, knows each script's real phase.)

**`rule test --live`** answers the same question **authoritatively**: it asks the
**running** proxy (`POST /admin/rule-test`, bearer-gated) to evaluate against its
**loaded** config using its own matcher and compiled scripts. That gives the exact
per-script phase (a response-only scrubber reads `response-phase; may rewrite the
response`) and the intercept decision, and it verifies what's *actually running*
— which may lag the edited TOML until `apply`/`start`. The default (offline) form
needs no running proxy and reflects the config file; `--live` needs the proxy up.

Rules ride the existing push path (`start` / `apply`), drift tracking (an
`applied-rules.json` sibling of `applied-bindings.json`), and `inspect`. Because
`/admin/config` is replace-all, **a rule edit re-pushes the whole config on the
next `apply`/`start`, re-fetching every binding's secret from its provider** — so
a credential-free rule change can still trigger a keychain/1Password prompt. A
rules-only update path is a possible follow-up.

## Authoring a rule script

A rule script is a `.star` file (resolved by name through the three-tier scripts
registry: user → profile → builtin) defining `on_request()` and/or
`on_response()`. It uses the same flat primitive API as scripted injectors —
`req_*` / `resp_*` reads and writes, `json_*`, `b64*`, `now` — **plus** two
terminal sinks:

- `block(status=403, reason=None)` — refuse the flow.
- `respond(status, body, headers)` — answer with a synthetic response.

**Restricted profile (enforced at compile time).** A rule script may **not** use
`secret()`, the `mint*` re-seal primitives, or the crypto/carrier primitives
(`hmac_sha256`, `sha256_hex`, `rs256_sign`, `jwt_encode_sign`, `b64_to_hex`, …).
A rule physically cannot touch credential material — so, unlike injector scripts,
**rule-script errors are reported in full** (message + location), a real
authoring-UX win. Referencing a forbidden primitive fails at config push with a
clear message.

**Fail-closed applies to your script too.** A rule-script hook that raises yields
a `502` (the flow is governed, never forwarded un-governed). Response rules also
run on upstream **error** responses, so a hook that assumes a 200-shaped body
should guard on `resp_status()` (and `resp_json() == None`) rather than let an
unexpected body raise into a 502.

Example (the builtin `scrub-emails`, a response-phase scrubber):

```python
def on_response():
    data = resp_json()
    if data == None:
        return
    if type(data) == "dict":
        _scrub(data)
    elif type(data) == "list":
        for item in data:
            if type(item) == "dict":
                _scrub(item)
    else:
        return
    resp_set_body(json_encode(data))

def _scrub(obj):
    for field in ("email", "notification_email"):
        if field in obj:
            obj[field] = None
```

A request-phase script that calls `block()`/`respond()` is terminal (short-
circuits injection); one that only mutates is non-terminal. A script that raises
fails closed (`502 credproxy: rule 'NAME' failed`).

## What the workspace sees

- **`/setup` gains a `rules` array** — name, hosts, methods, path, action kind
  only (never script source; **hidden rules excluded**). Same least-disclosure
  philosophy as bindings.
- **`/llms.txt`** carries one standing sentence regardless of configuration:
  *"responses on intercepted hosts may be modified or refused by policy; listed
  rules are not necessarily exhaustive."*
- A **visible** synthetic response self-identifies (`X-Credproxy-Rule` +, for a
  block, the `{"credproxy": …}` body) so an agent can tell policy from upstream.

## Audit

Every rule hit — visible or hidden — emits exactly one structured audit event
naming the rule (`[audit] {"event":"rule","rule":"…","action":"…","outcome":"…"}`),
retrievable with `credproxy workspace NAME logs --audit`. No event ever carries a
secret value or a header value. Hidden-rule hits being audited is what makes a
tripwire useful.
```
