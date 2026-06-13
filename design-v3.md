# credproxy — Design v3: the credential injection model

**Status: design, not yet implemented.** This document specifies the
scheme-aware credential-injection model that replaces v2's single mechanism
(substring-replace a placeholder in one header). It builds on `design-v2.md`,
which remains the product design of record for everything else (workspaces,
the two surfaces, providers-as-executables, the push model, host-scoping). It
resolves two items design-v2 explicitly deferred: the **injector/provider
authoring contract** and the **`format` / inject-transform** open question.

---

## Motivation

v2 substitutes a placeholder for a real value **inside one request header**,
as a literal substring replace. Real-world testing (issues #3–#5) showed that
model has a hard ceiling — one credential routinely spans multiple hosts,
schemes, and wire locations:

- **#3 GitHub.** A token is `Bearer` on `api.github.com` but HTTP **Basic**
  (`base64(user:token)`) on `github.com`. Substring-replace can't reach inside
  the base64 blob, forcing hand-computed `base64(user:placeholder)` placeholders
  and a fragile coupling between bindings.
- **#4 OAuth2 client-credentials** (Azure AD, runZero, …). The secret rides in
  the **request body** (`client_secret=…`), not a header — unreachable today.
- **#5 request-signing** (AWS SigV4, OVH, GCP service-account JWT). The secret
  is a **signing key**; it never transits the wire. There is no static value to
  swap — the proxy must *compute* the signature.

The fix is to make injection a **typed, scheme-aware request transform**, with a
small fixed set of trusted mechanisms plus a sandboxed scripting escape hatch
for the long tail. Prior art studied: superfly/tokenizer (typed processor union;
substitute *and* sign families; two-phase request+response token minting;
`StripHazmat` redaction) and denoland/clawpatrol (detect-vs-apply decoupling;
multi-slot secrets; per-service plugins). Both went *compiled*; we diverge with
a lightweight scripting escape hatch that matches credproxy's drop-a-file ethos.

---

## Core model: injection schemes

An **injector** selects a typed **scheme** the proxy implements, parameterized
for the service. Schemes fall into two families:

- **Substitute (placeholder-driven).** The workspace holds an inert placeholder
  and sends it; the proxy finds it in the scheme's location and swaps in the
  real value, decoding/re-encoding as the scheme dictates.
- **Sign (compute-on-the-fly).** No usable static value on the wire; the proxy
  holds the signing key (pushed, as always) and computes the auth material per
  request. The workspace sends an unsigned or placeholder-signed request.

### Scheme catalog

| Scheme | Family | Built-in | Covers |
|---|---|---|---|
| `bearer` | substitute | done | most REST APIs (GitHub PAT, OpenAI, Stripe…) |
| `basic` | substitute | done | git over HTTPS, registries, any HTTP Basic |
| `body` | substitute | done | OAuth2 client-creds (Azure/runZero), key-in-body |
| `header` | substitute | next | arbitrary custom-header / cookie / query keys |
| `sigv4` | sign | done | AWS + all S3-compatible services |
| `hmac` | sign | later | webhook-style body signatures |
| `jwt-bearer` | sign/mint | later | GCP SA, GitHub App, Snowflake (RS256 assertion) |

The set of *mechanisms* is small and slow-moving; the explosion of services
rides on top as **configuration** (host + params), not code. A new service
almost always means new params/preset, not a new scheme. Only a genuinely novel
algorithm (e.g. OVH's sha1-concat signature) earns a new scheme.

### `basic` decode-and-swap (resolves #3, decision 1)

The proxy decodes `Authorization: Basic`, swaps the **password** component for
the real value, and re-encodes. Consequences:

- the placeholder is a **bare token** — no hand-computed base64, ever;
- the **username comes from the wire** (the client already built the blob), so
  no username config;
- the **same bare-token placeholder** works as `bearer` on `api.github.com` and
  `basic` on `github.com` — the cross-binding coupling disappears.

A **`--preset github`** generates the (bearer@api, basic@github[, basic@ghcr])
binding set sharing one bare-token placeholder. The end-state UX of #3 with the
footgun structurally removed, not hidden.

---

## The transform interface

Every scheme — built-in or scripted — is expressed against one interface, so
the two are interchangeable:

- `on_request(ctx)` — mutate the outbound request.
- `on_response(ctx)` — *optional*; mutate the response (only the sign/mint and
  re-seal schemes use it; see Re-seal). Wired from day one, no-op until used.
- a set of **trusted utility primitives** the proxy provides: header get/set,
  body read/replace, `b64encode`/`b64decode`, `hmac_sha256`, `sigv4_sign`,
  `jwt_sign`, and `secret(slot="value")` — the **only** door to the real value.

The crypto and encoding (the security/correctness-sensitive code) is **built-in
and trusted**; schemes only *orchestrate* it. This keeps "we own the crypto"
while making composition open.

---

## Extensibility: escape-hatch (decision 4, evolved)

v2's "fixed scheme set" evolves to: **fixed trusted primitives + built-in
schemes (the common 95%) + Starlark injector scripts as the escape hatch** for
the long tail and per-service quirks.

- **Built-in schemes are Python** (`bearer`/`basic`/`body`/`header`/`sigv4`…),
  implemented against the transform interface above — fast on the hot path, no
  interpreter overhead for the common case.
- **Scripted injectors are Starlark**, run *in the proxy*, via
  [`starlark-pyo3`](https://github.com/inducer/starlark-pyo3) (PyO3 wrapper over
  Meta's starlark-rust; prebuilt manylinux cp312 wheels, so no Rust in the proxy
  image). A scripted injector is just a more powerful injector file — parallel to
  providers being executables, but **sandboxed** because injectors run in the
  proxy with secret access (providers run on the host, in the user's own
  context, so they need no sandbox).
- The built-in schemes are **also re-implemented as bundled Starlark scripts**,
  serving triple duty: dogfood the scripting interface, ship as authoring
  examples/templates, and provide a direct **Python-vs-Starlark per-request
  benchmark** (the one perf number the library docs can't give us).

### Starlark injector contract

- The script defines `on_request(ctx)` (and optionally `on_response(ctx)`),
  called via `FrozenModule.call(...)`.
- The proxy injects primitives via `Module.add_callable(...)` and passes the
  request as an `OpaquePythonObject` (the script can't introspect it, only act
  on it through the registered callables).
- **Sandbox (load-bearing):** `dialect.enable_load = False`, only
  `Globals.standard()` plus our primitives — **no I/O, no network, no
  filesystem, no `import`/`exec`**. A script can only shape the request bound for
  the binding's already-fixed host. So even a *shared third-party* injector
  cannot exfiltrate the secret: it has no I/O and can't choose the destination
  (host-scoping lives in the binding, outside the script). This makes a scripted
  injector strictly *more* contained than the provider executables we already
  accept.
- **Resource bounds (the one gap):** the binding exposes no step/time limit.
  Mitigation: run each script in a thread executor with a timeout and **fail the
  flow closed** on overrun. A runaway is a recoverable DoS of one workspace's
  proxy (within the documented "DoS-or-config-replace" ceiling), never an
  exfiltration. Longer term: expose starlark-rust's step limit upstream.
- The **workspace can never supply a script** — injectors are host-authored
  control-plane config (the door model), same trust boundary as v2's injector
  TOML.

---

## Multi-slot secrets (decision 2)

Some schemes need more than one value (`sigv4` = access_key_id +
secret_access_key; future mTLS = cert + key + ca). Model:

- A scheme declares its **slot names** (built-in to the scheme).
- The binding maps slot → provider ref. Single-slot stays a bare string:
  ```toml
  secret = "GITHUB_TOKEN"                  # single-slot sugar

  [binding.secret]                          # multi-slot
  access_key_id     = "AWS_ACCESS_KEY_ID"
  secret_access_key = "AWS_SECRET_ACCESS_KEY"
  ```
- One provider per binding; resolved per slot.

### Provider protocol v2 (batch-native)

The provider protocol becomes batch-native (one invocation per binding, so an
interactive provider prompts **once** for a multi-slot credential, and a vault
provider can coalesce same-item refs into one fetch):

```
request  (stdin):  {"version":1, "op":"get", "secrets":["<ref>", ...]}
response (stdout): {"values": {"<ref>":"<value>", ...}}        exit 0
```

The provider deals only in **refs**, not credproxy slot names — the slot↔ref
mapping stays in the binding (CLI-side). Single value = a list of one; there is
no single/batch duality. Breaking change vs v2's `{secret}`→`{value}`; fine
pre-release. The bundled `env` provider is rewritten to loop over the list.

Multi-slot mirrors on the **placeholder** side too: a sign scheme like `sigv4`
needs the workspace to hold *placeholder* AWS creds so its SDK produces a
(useless) signed request the proxy re-signs — so `/setup` exposes per-slot
placeholders/env.

---

## Minted tokens: pass-through now, re-seal designed-for (decision 3)

Some flows mint a short-lived token from a durable secret (OAuth2
client-credentials, GCP SA JWT, GitHub App). The decision is where the minted
token ends up.

- **Pass-through (now).** The proxy transforms only **requests**; the minted
  short-lived token flows back to the workspace and is used there directly. The
  **durable** secret (client_secret, SA key, PAT, AWS key) never enters the
  workspace. The proxy stays response-blind and stateless about tokens. (For
  client-credentials this is just `body` substitution — the token endpoint
  returns the access token to the workspace; no special handling.)
- **Re-seal (planned additive extension).** The proxy intercepts the
  token-endpoint **response**, holds the minted token (TTL), hands the workspace
  a placeholder, and swaps it on subsequent API-host requests — so even the
  short-lived token never lands in the workspace. We will add this; we are not
  building it first.

### Re-seal seams to build now (so it's additive, not a rewrite)

The unifying insight: **a dynamic placeholder is just a static placeholder the
proxy mints at runtime and registers in the same substitution table, with a
TTL.** The data-plane swap is identical. So re-seal needs only a response-side
mint+register and TTL eviction on top of pass-through. The seams to bake in:

1. **Two-phase scheme interface** — `on_request` + optional `on_response`, with
   the `response` hook plumbed from day one (no-op until a scheme uses it).
2. **Open, scheme-defined `params`** in the binding and wire envelope (a future
   `jwt-reseal` carries `token_endpoint`, `api_hosts`, TTL hints with no schema
   churn).
3. **Substitution lookup as a function over (static pushed config + a
   runtime-augmentable layer)** — never bake the substitution set into an
   immutable structure at push time. Dynamic entries are just a runtime layer.
4. **Placeholder generator callable proxy-side** (not only CLI-side) — dynamic
   placeholders reuse the same prefix/length/charset pattern, so the pattern must
   be available to the proxy for re-seal schemes.
5. **Do not globally enable mitmproxy response streaming** — re-seal must buffer
   and rewrite the token-endpoint response body.

Two constraints to honor (no code now): a credential's flow may span multiple
hosts (mint at token endpoint, use at API host — expressed via scheme params);
and the proxy will hold transient TTL'd token state in `AppState` later.

The push model is unchanged either way: the CLI pushes only durable secrets;
re-seal adds proxy-side *runtime derivation* of short-lived tokens from them.

---

## Wire format & config

**Wire push (`POST /admin/config`):** each binding carries a `scheme`, an opaque
scheme-defined `params`, and a structured `secret` keyed by slot:

```json
{"bindings": [{
  "name": "github-git", "hosts": ["github.com"],
  "scheme": "basic", "params": {"header": "Authorization"},
  "secret": {"value": "<real>"}, "env": "..."
}]}
```

The proxy dispatches on `scheme`. `real: str` generalizes to `secret: {slot:
value}` (single-slot uses a default `value` slot).

**Injector (declarative):** selects a scheme + params + placeholder pattern.
**Scripted injector:** a `.star` file defining `on_request`/`on_response`.
**Binding:** unchanged shape (injector, provider, secret, hosts), with `secret`
now str-or-table. **Preset:** a CLI-side config generator (e.g. `github`).

**Inward `/setup`:** continues least-disclosure (name, placeholder, env, header,
hosts — plus per-slot placeholders for multi-slot; never provider/secret-id/real).

---

## Sequencing

1. **Transform core + Python built-ins** (`bearer`, `basic`, `body`), designed
   against the transform interface; provider protocol v2 (batch); multi-slot
   secret model; `basic` decode-and-swap + `--preset github`. Closes #3, #4.
   **(Done.)**
2. **`sigv4`** (sign family) — closes #5a. Validates the sign-family shape. The
   proxy re-signs: the workspace's SDK signs with throwaway creds, the proxy
   reads the scope it chose, recomputes the canonical request, and re-signs with
   the real key (verified against AWS's published IAM ListUsers vector).
   **(Done.)**
3. **Starlark runtime** (escape hatch) + the bundled Starlark re-implementations
   of the built-ins (dogfood/examples/benchmark) + the timeout wrapper. Closes
   the long tail (#5b OVH, `jwt-bearer`, quirks) as scripts.
   - **3a (done):** `proxy/starlark_runtime.py` (`ScriptedScheme` + trusted
     primitives + `Globals.standard()` sandbox, `load()` neutralized, thread+
     timeout failing closed) via `starlark-pyo3`; bundled `proxy/scripts/`
     dogfood of bearer/basic/body, proven behaviourally identical to the Python
     built-ins, with a Python-vs-Starlark benchmark. **Not yet wired into config
     dispatch** — see 3b.
   - **3b (next):** the scripted-injector authoring contract — the injector TOML
     declares `scheme = "script"`, the `.star` file, and `family`/`slots`/
     `location_kind` (the host CLI stays declarative; only on_request/on_response
     live in the script); plus `jwt-bearer`/OVH as worked examples.
4. **Re-seal** (the response-phase + dynamic-placeholder store), as the additive
   extension the seams above anticipate.

---

## Open questions

- **Re-seal token-endpoint disambiguation.** When multiple bindings mint at the
  same token endpoint, the request-phase must match the specific binding via a
  trigger placeholder *in the request* (body/header), not just the host. Needs
  pinning down per provider.
- **Sign-family per-service quirks** (S3 payload signing, GitHub App's two-step
  installation-token dance, exact GCP claims) must be expressible as scheme
  *params*; a service needing imperative special-casing is a signal to add a
  script, not a branch.
- **Interactive OAuth with refresh** (authorization-code + refresh tokens) is
  out of scope for now.
- **Built-in vs Starlark for the hot path** — built-ins are Python; the
  benchmark from the dogfood Starlark versions decides whether scripted injectors
  are ever fast enough to be the *only* implementation (not planned, but measured).
  **Measured (3a):** the Starlark bearer is ~56× the Python built-in per call
  (~215µs vs ~3.8µs), dominated by the thread-hop the fail-closed timeout
  requires. Negligible against network latency (fine for the long tail), but it
  confirms the built-ins stay Python on the hot path.
