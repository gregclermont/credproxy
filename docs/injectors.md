# Injectors

An **injector** defines *how* a credential is shaped into a request for a
service: which typed **scheme** the proxy runs, the scheme's params, and the
shape of the inert placeholder the workspace holds. It is the passive,
service-specific counterpart to a [provider](providers.md) (which defines
*where* the value comes from). A [binding](configuration.md#bindings) ties the
two together.

Unlike providers — which are executables — injectors are **declarative TOML
files**: passive, reusable, drop-in. The filesystem is the registry; there is
nothing to install.

## Schemes

The proxy implements a small, fixed set of typed **schemes** (design-v3). An
injector picks one and parameterizes it; the explosion of services rides on top
as configuration, not code. Schemes fall into two families:

- **substitute** — the workspace holds an inert placeholder and sends it; the
  proxy finds it in the scheme's wire location and swaps in the real value,
  decoding/re-encoding as needed.
- **sign** — no usable static value on the wire; the proxy holds a signing key
  and computes the auth material per request.

| Scheme | Family | Params | Slots | Covers |
|---|---|---|---|---|
| `bearer` | substitute | `header` (default `Authorization`) | `value` | most REST APIs (PATs, OpenAI, Stripe, …) |
| `basic` | substitute | `header` (default `Authorization`) | `value` | git-over-HTTPS, registries, any HTTP Basic |
| `body` | substitute | — | `value` | OAuth2 client-credentials, key-in-body APIs |
| `oauth2-reseal` | substitute | `api_hosts` (required), `token_field`, `expires_field`, `ttl`, `reseal_header` | `value` | OAuth2 client-credentials where even the minted token must stay out of the workspace |
| `sigv4` | sign | — | `access_key_id`, `secret_access_key` | AWS + all S3-compatible services |

`bearer` substring-swaps the placeholder for the real value inside the named
header (any `Bearer `/`token ` prefix the client sent is left intact). `basic`
decodes the `Authorization: Basic` blob, swaps the component equal to the
placeholder (password by default, or username), and re-encodes — so the
placeholder is a **bare token**, never hand-computed base64. `body` swaps the
placeholder anywhere in the request body.

`sigv4` (sign family) is different: the AWS secret is a *signing key* that never
transits the wire, so there is no placeholder. The workspace's AWS SDK signs
each request with **throwaway** credentials; the proxy reads the credential
scope (region/service) the SDK chose from the incoming `Authorization`,
recomputes the canonical request, and re-signs it with the real key. It is a
**multi-slot** scheme (`access_key_id` + `secret_access_key`); region and
service are read from the request, so it takes no params.

`oauth2-reseal` (substitute family) closes the gap plain pass-through leaves
open. Pass-through keeps the *durable* client secret out of the workspace, but
the short-lived token the OAuth2 token endpoint mints still lands there.
Re-seal holds that token in the proxy too. On the **request** phase it behaves
like `body`: the workspace sends the token-endpoint request with a placeholder
where `client_secret` goes (`location_kind = body`, single `value` slot), and
the proxy swaps placeholder→real secret. On the **response** phase it parses the
token-endpoint response, extracts the minted token from `token_field` (default
`access_token`), registers a TTL'd `bearer` swap (a freshly-minted dynamic
placeholder → the real token) on the `api_hosts`, and rewrites the response body
so the workspace receives the *placeholder* instead of the token. The TTL comes
from the response's `expires_field` (default `expires_in`), falling back to the
`ttl` param (default `3600` seconds) when the response omits it; once it elapses
the runtime swap is evicted. When the workspace later calls an API host with that
placeholder, the request-phase swap (in the `reseal_header`, default
`Authorization`) substitutes the real minted token — which thus never enters the
workspace. A *dynamic* placeholder is just a static one registered at runtime
with a TTL; the data-plane swap reuses the `bearer` substitute.

The binding is scoped (via `--host`) to the **token endpoint** host. The
`api_hosts` param lists the hosts where the minted token is used; they are
TLS-terminated so the swap applies there too. Several re-seal bindings can share
one token endpoint (e.g. multiple OAuth2 apps on a multi-tenant IdP): each is
told apart by its own placeholder in the request, and the response is re-sealed
only for the binding that fired on that request — so app A's token only ever
lands on app A's `api_hosts`. Because `api_hosts` is
deployment-specific, you **copy** the bundled `oauth2-reseal` injector to
`$XDG_CONFIG_HOME/credproxy/injectors/` and edit `api_hosts` (a user injector
shadows the bundled one) — the same copy-to-edit pattern as `jwt-bearer`. A
bundled **scripted** twin, `oauth-reseal` (scheme `script`), demonstrates the
same flow via the [`mint`](#scripted-injectors-the-escape-hatch) primitives; use
it as the escape-hatch template when you need to customize re-seal beyond the
built-in scheme's params.

## Discovery

An injector is referenced by `<name>`. Lookup order (first match wins, so a user
definition shadows a bundled one of the same name):

1. `$XDG_CONFIG_HOME/credproxy/injectors/<name>.toml` (default
   `~/.config/credproxy/injectors/<name>.toml`)
2. Bundled with the tool at `cli/credproxy_cli/bundled/injectors/<name>.toml`

`credproxy injector list` shows every resolvable injector and its source
(`user` or `bundled`).

## Schema

```toml
scheme = "bearer"             # required: a scheme name from the table above
env    = "GITHUB_TOKEN"       # optional: suggested workspace env var

[params]                      # optional; scheme-specific (defaults merged in)
header = "Authorization"      #   bearer/basic: the header the credential rides in

[placeholder]                 # optional; pattern for the inert sentinel
prefix  = "ghp_"
length  = 40                  # total length including the prefix
charset = "alnumeric"         # alnumeric | hex | base64url
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `scheme` | string | — (required) | The typed scheme the proxy runs. Must be a known scheme. |
| `[params]` | table | scheme defaults | Scheme-specific settings, merged onto the scheme's defaults and passed to the proxy verbatim. For `bearer`/`basic`, `header` selects the header. |
| `env` | string | none | Suggested workspace-side env var name, surfaced via `/setup` and used as a binding's `env` default. |
| `[placeholder]` | table | the default pattern | Shape of the generated sentinel. Omit to use `prefix = "credproxy_"`, `length = 40`, `charset = "alnumeric"`. |
| `placeholder.prefix` | string | `"credproxy_"` | Literal leading characters. |
| `placeholder.length` | integer | `40` | Total length **including** the prefix. Must exceed the prefix length. |
| `placeholder.charset` | string | `"alnumeric"` | Alphabet for the random body. One of the charsets below. |

### Charsets

| Name | Alphabet |
|---|---|
| `alnumeric` | `A–Z`, `a–z`, `0–9` (the safe, widely format-valid default) |
| `hex` | `0–9`, `a–f` |
| `base64url` | `A–Z`, `a–z`, `0–9`, `-`, `_` |

Validation errors (missing/unknown `scheme`, a non-table `[params]`, an unknown
`charset`, a `length` not exceeding the prefix, a non-string `env`, …) are
reported as an injector error naming the file and field.

## Placeholders

The placeholder is the inert sentinel the workspace actually holds and the agent
actually sends. It is generated as `prefix` followed by random characters drawn
from `charset` (via Python's `secrets`) to reach `length`. The point is to be
**format-valid for the service** — the right prefix, length, and character set —
so client-side token-format checks pass, while the real value never leaves the
host.

A placeholder is generated **once**, when the binding is first materialized, and
written back into the workspace's config file so the workspace's environment and
the proxy's expectation can never drift. The injector only supplies the
*pattern*; the concrete value lives on the binding. See
[materialization](configuration.md#bindings).

Because injection is now scheme-aware, you send the credential the natural way
for the service (e.g. `Authorization: Bearer <placeholder>`, or a
`base64(user:<placeholder>)` Basic blob your git client builds itself) and the
scheme does the right transform in transit. There is no `format` field — the
scheme owns the wire shape.

## Bundled injectors

| Name | Scheme | Params | Placeholder | env hint |
|---|---|---|---|---|
| `bearer` | `bearer` | `header = Authorization` | default (`credproxy_` + 30 alnum, 40 total) | none |
| `basic` | `basic` | `header = Authorization` | default | none |
| `body` | `body` | — | default | none |
| `oauth2-reseal` | `oauth2-reseal` | `api_hosts` (edit before use), `token_field`, `expires_field`, `ttl`, `reseal_header` | default | none |
| `sigv4` | `sigv4` | — | none (sign family) | none |

A `sigv4` binding uses a multi-slot secret, e.g.:

```sh
credproxy workspace NAME binding add --injector sigv4 --provider env \
    --secret access_key_id=AWS_ACCESS_KEY_ID \
    --secret secret_access_key=AWS_SECRET_ACCESS_KEY \
    --host '*.amazonaws.com'
```

`sigv4` reads the region and service from each request, so a single
`*.amazonaws.com` glob host covers every regional endpoint (`s3.us-east-1…`,
`dynamodb.eu-west-1…`) with one key — scope it tighter with `s3.*.amazonaws.com`
or a literal `sts.amazonaws.com` if you prefer. See [host
patterns](configuration.md#host-patterns) for the glob rules.

In the workspace, configure any throwaway AWS credentials (e.g. dummy
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) so the SDK produces a signed
request for the proxy to re-sign.

`bearer` doubles as the scaffold template for new injectors. A GitHub PAT, which
is `bearer` on `api.github.com` but HTTP `basic` on `github.com`/`ghcr.io`, is
generated as a coordinated set by `binding add --preset github` (the three
bindings share one bare-token placeholder) — see
[configuration.md](configuration.md#bindings).

## Authoring your own

`credproxy injector scaffold NAME` copies the bundled `bearer` template to
`$XDG_CONFIG_HOME/credproxy/injectors/NAME.toml` (it refuses to overwrite an
existing file). Edit it, then reference it from a binding:

```sh
credproxy injector scaffold acme
$EDITOR ~/.config/credproxy/injectors/acme.toml
credproxy workspace myproj binding add \
    --injector acme --provider env --secret ACME_KEY --host api.acme.example
```

A worked custom injector — an API that wants the key bare in a custom header,
with service-shaped placeholders:

```toml
# ~/.config/credproxy/injectors/acme.toml
scheme = "bearer"           # substring-swap in a header
env    = "ACME_API_KEY"

[params]
header = "X-Acme-Key"       # the key rides here, sent verbatim

[placeholder]
prefix  = "acme_"
length  = 32
charset = "hex"
```

Because a binding's `placeholder` and `env` are materialized from the injector
the first time the binding is loaded, change an injector's pattern *before*
creating bindings that use it; existing bindings keep their already-materialized
values (the file stays the source of truth). To re-shape an existing binding,
edit or clear its `placeholder` in the workspace config.

## Scripted injectors (the escape hatch)

When the built-in schemes can't express a service's auth (a bespoke signature, a
multi-step token mint), an injector can run a **Starlark script** in the proxy
instead. The injector TOML stays declarative — it sets `scheme = "script"`,
names a `.star` file, declares the primitive-API version it targets (`api`), and
declares the metadata the host CLI can't infer by reading Starlark (`family`,
`slots`, and the wire `location_kind`). The script carries only the logic:
`on_request()` (and optionally `on_response()`).

```toml
# ~/.config/credproxy/injectors/myservice.toml
scheme = "script"
script = "myservice"         # resolves myservice.star (user dir, then bundled)
api    = 1                   # primitive-API version the script targets (default 1)
family = "sign"              # "substitute" (placeholder) | "sign" (no placeholder)
slots  = ["value"]           # secret slot names the script reads
location_kind = "header"     # where it writes, for host-collision detection
env    = "MYSERVICE_TOKEN"

[params]                      # passed to the script verbatim (read via param())
header = "X-MyService-Auth"
```

```python
# ~/.config/credproxy/scripts/myservice.star
def on_request():
    req_set_header(param("header", "Authorization"), "Bearer " + secret())
    return True
```

The hook takes **no arguments**. There is no `ctx` to thread: the request and
response context is implicit — the runtime binds it around each call, and the
flat primitives below read and mutate it directly. A script never receives,
holds, or passes a context handle.

The script discovery mirrors injectors/providers (`$XDG_CONFIG_HOME/credproxy/
scripts/<name>.star`, then the bundled set). At `start`/`apply`/`binding test`
the CLI reads the `.star` **source** and pushes it to the proxy with the config
(the push model — the proxy stays stateless and compiles what it's given, so
your scripts work with no mounts or image rebuilds).

### API version

The `api` field declares which primitive-API version the script targets. It is
**optional and defaults to `1`** (the current version), is pushed on the wire
with the rest of the binding, and the proxy validates it against the versions it
implements — a binding whose version the proxy can't run is rejected with a
clear error rather than silently mis-injecting. This is the forward-compatibility
seam: if a future release changes the primitive surface incompatibly, it bumps
the version, and an injector pins the version it was written against so an older
script keeps running against the semantics it expects.

**Sandbox.** The script runs in the proxy with access to the real credential via
`secret()`, so it is sandboxed. `Globals.standard()` is the entire language
surface available: there is no `print`, I/O, filesystem, network, `import`, or
`exec`, `load()` is neutralized, and there is **no `try`/`except`** in Starlark.
Only the trusted primitives below are callable; the crypto and encoding among
them are owned by the proxy, so scripts orchestrate cryptography but never
implement it. A script can only shape the request bound for the binding's
already-fixed host — host-scoping lives in the binding, outside the script — so
even a shared third-party script can't choose a destination or exfiltrate the
secret. See `proxy/starlark_runtime.py`.

**Fail-closed.** Any uncaught error in a hook makes the proxy skip injection and
forward the request **unmodified**. The error is logged by **exception type
only**, never its message — so a script cannot do something like `fail(secret())`
to leak the credential into a log. A hook also signals its outcome by return
value: return `True` if it acted, `False` to no-op (which also fails closed —
the request is forwarded unmodified).

**Total vs. partial reads.** The primitives follow one convention: a read for
something that is merely *absent* returns `None` (test it with `== None`), while
genuinely corrupt input or author error — bad base64, an unknown secret slot,
invalid JSON passed to `json_decode` — **raises**, which fails closed. So
`resp_json()` and `jwt_decode_or_none()` are *total* (None on anything malformed,
no `try`/`except` needed), whereas `json_decode()` is *partial* (raises on bad
input).

### Primitives available to scripts

A script defines `on_request()` (return `True` if it injected, `False` to skip)
and optionally `on_response()`. Both hooks are **zero-arg** — the context is
implicit. Function names must not start with `_`.

The stateful primitives are flat top-level functions that read or mutate the
implicit context; there is no `ctx` parameter to thread. Their `req_`/`resp_`
prefix also encodes the **phase** they belong to:

- `req_` **getters** (`req_method`, `req_path`, `req_host`, `req_header`,
  `req_body`, `req_body_b64`) work in **both** phases — in `on_request()` they
  read the live outbound request; in `on_response()` they read the request that
  was answered.
- `req_set_*` **mutators** are **request-phase only** — calling `req_set_header`
  or `req_set_body` from `on_response()` raises (→ fail closed).
- `resp_*` (and the re-seal `mint`/`mint_into_json`) are **response-phase
  only** — calling any of them from `on_request()` raises (→ fail closed). The
  response phase is where design-v3 phase-4 re-seal runs.

**Credential & binding**

| Primitive | Returns | Purpose |
|---|---|---|
| `secret(slot="value")` | `str` | The resolved real credential for a slot — the **only** door to the secret. Raises on an unknown slot (→ fail closed). |
| `placeholder()` | `str\|None` | The inert placeholder string (substitute family); `None` for the sign family. |
| `param(key, default=None)` | `str` | A scheme param from the injector's `[params]`. |

**Request — reads (both phases)**

| Primitive | Returns | Purpose |
|---|---|---|
| `req_method()` | `str` | The request method (read-only). |
| `req_path()` | `str` | The request path including query string (read-only). |
| `req_host()` | `str` | The request host (read-only). |
| `req_header(name)` | `str\|None` | A request header value, or `None` if absent. |
| `req_body()` | `str\|None` | The request body as text, or `None`. |
| `req_body_b64()` | `str\|None` | The request body's raw bytes as base64 (binary-safe), or `None`. |

**Request — mutation (request phase only)**

| Primitive | Returns | Purpose |
|---|---|---|
| `req_set_header(name, value)` | — | Set/replace a request header. |
| `req_set_body(text)` | — | Replace the request body. |

**Response (response phase only — phase-4 re-seal seam)**

| Primitive | Returns | Purpose |
|---|---|---|
| `resp_status()` | `int` | The response status code. |
| `resp_header(name)` | `str\|None` | A response header value, or `None` if absent. |
| `resp_set_header(name, value)` | — | Set/replace a response header. |
| `resp_body()` | `str\|None` | The response body as text, or `None`. |
| `resp_set_body(text)` | — | Replace the response body. |
| `resp_json()` | `dict\|None` | The response body parsed as JSON, or `None` if absent / not valid JSON (**total** — branch on `== None`, no `try`/`except`). |

**Re-seal (response phase only)**

These mint a re-seal swap from a token the proxy just intercepted. They are
**response-phase only** — calling either from `on_request()` raises (→ fail
closed). The target hosts and header come from the binding **params**
(`api_hosts` and `reseal_header`, default `Authorization`), not primitive args,
so a re-seal script supplies only `value` + `ttl`.

| Primitive | Returns | Purpose |
|---|---|---|
| `mint(value, ttl)` | `str` | Register a runtime swap (a freshly-minted placeholder → `value`) on the binding's `api_hosts` param for `ttl` seconds, and return the placeholder. The target header is the binding's `reseal_header` param (default `Authorization`). |
| `mint_into_json(field, value, ttl)` | `str` | `mint(value, ttl)`, then rewrite the response body's JSON `field` to the placeholder (so the workspace receives the placeholder, not the real token). Parses the body before registering, so a non-JSON body fails closed without leaving a dangling runtime entry. Returns the placeholder. |

The pure primitives take no context and are deterministic (except `now`/`now_ms`).

**Encoding**

| Primitive | Returns | Purpose |
|---|---|---|
| `b64encode(s)` | `str` | Standard base64-encode a UTF-8 string. |
| `b64decode(s)` | `str` | Standard base64-decode to a UTF-8 string. |
| `b64url_encode(s)` | `str` | Unpadded URL-safe base64 (the JWT/JWS form). |
| `b64url_decode(s)` | `str` | Decode unpadded URL-safe base64 to a UTF-8 string. |
| `b64_to_hex(b64)` | `str` | **Carrier** transcode: re-encode raw bytes from base64 to hex **without** a UTF-8 round-trip. |
| `hex_to_b64(hex)` | `str` | **Carrier** transcode: re-encode raw bytes from hex to base64. |

**Hashing & signing**

| Primitive | Returns | Purpose |
|---|---|---|
| `hmac_sha256(key_b64, msg)` | `str` | **Carrier** HMAC-SHA-256: key is base64 of the raw key bytes, output is base64 of the raw MAC — chains output→next-key for multi-round key derivation. |
| `hmac_sha256_hex(key, msg)` | `str` | Convenience HMAC-SHA-256: text key in, hex out (the common single-shot case). |
| `sha256_hex(s)` | `str` | Hex SHA-256 digest of a UTF-8 string. |
| `sha1_hex(s)` | `str` | Hex SHA-1 digest of a UTF-8 string. |
| `rs256_sign(pem, msg)` | `str` | RS256 (RSASSA-PKCS1-v1_5 / SHA-256) signature over `msg`, as unpadded base64url. `pem` is a PKCS#8/PKCS#1 RSA private key. |

**JWT**

| Primitive | Returns | Purpose |
|---|---|---|
| `jwt_encode_sign(header, claims, pem)` | `str` | Build a **signed** RS256 JWS compact token from `header`/`claims` dicts. Owns segment assembly, base64url padding, and signing the right bytes. Returns the `a.b.c` token. |
| `jwt_decode_or_none(token)` | `dict\|None` | The JWT claims (middle segment) as a dict, or `None` if not a well-formed JWT. **Does not verify** the signature (for reading a token you're re-sealing, not trusting). |

**JSON & time**

| Primitive | Returns | Purpose |
|---|---|---|
| `json_encode(value)` | `str` | Compact, deterministic JSON of a Starlark value (dict/list/str/int/bool/None). |
| `json_decode(s)` | value | Parse a JSON string to a Starlark value. **Raises** on invalid input (→ fail closed; contrast the total `resp_json()`). |
| `now()` | `int` | Current Unix time, seconds. |
| `now_ms()` | `int` | Current Unix time, milliseconds. |

The crypto and encoding primitives are owned and trusted by the proxy; scripts
orchestrate them and never implement crypto. Note the **carrier** forms
(`hmac_sha256` + `b64_to_hex`/`hex_to_b64`): because the carrier-HMAC key and
output are both base64 of *raw bytes*, the output of one round chains straight
into the key of the next without a lossy UTF-8 round-trip — that is what makes a
multi-round derivation like AWS SigV4's
`hmac(hmac(hmac(hmac("AWS4"+secret, date), region), service), "aws4_request")`
expressible, ending the chain with `b64_to_hex(...)` for a hex signature. The
Starlark environment has no JSON builtin or f-strings — use `json_encode()` /
`json_decode()` for JSON and `+` for string concatenation.

### Bundled scripted injectors

Two sign-family examples and a re-seal example ship as bundled injectors.

**`ovh`** — signs OVH API requests. Sets `X-Ovh-Application`,
`X-Ovh-Consumer`, `X-Ovh-Timestamp`, and `X-Ovh-Signature` (`"$1$" +`
`sha1_hex` over the concatenated signing string, which includes the method,
full URL, and body read via `req_method()`/`req_host()`/`req_path()`/
`req_body()`). Slots: `app_key`, `app_secret`, `consumer_key`.

```sh
credproxy workspace NAME binding add --injector ovh --provider env \
    --secret app_key=OVH_APP_KEY \
    --secret app_secret=OVH_APP_SECRET \
    --secret consumer_key=OVH_CONSUMER_KEY \
    --host eu.api.ovh.com
```

**`jwt-bearer`** — mints a self-signed RS256 JWT assertion from an RSA private
key and sets `Authorization: Bearer <jwt>`. Slot: `private_key`. Params:
`iss`, `aud`, `ttl` (set in the injector TOML; copy it to your user injectors
dir to customize, since a user injector shadows the bundled one).

```sh
credproxy workspace NAME binding add --injector jwt-bearer --provider env \
    --secret private_key=GCP_SA_PRIVATE_KEY --host api.example.com
```

A representative excerpt from `jwt-bearer.star` showing how the primitives
compose:

```python
def on_request():
    now_ts = now()
    ttl    = int(param("ttl", "3600"))

    jwt = jwt_encode_sign(
        {"alg": "RS256", "typ": "JWT"},
        {
            "iss": param("iss"),
            "aud": param("aud"),
            "iat": now_ts,
            "exp": now_ts + ttl,
        },
        secret("private_key"),
    )

    req_set_header("Authorization", "Bearer " + jwt)
    return True
```

`jwt_encode_sign()` owns the JWS assembly — base64url-encoding each segment,
joining `header.claims`, signing exactly those bytes, and appending the
signature — so the script never hand-builds `b64url_encode(header) + "." + …`
and feeds it to a separate signer. That hand-assembly is the classic JWS
footgun (mis-encoded padding, signing the wrong bytes) this primitive removes.

**`oauth-reseal`** — the scripted twin of the built-in `oauth2-reseal` scheme,
demonstrating re-seal via the `mint` primitives. Its injector manifest sets
`location_kind = "body"` and a `[params] api_hosts = [...]` list (copy it to your
user injectors dir and edit `api_hosts`). The script swaps the `client_secret`
placeholder into the token-endpoint request (request phase), then on the
response mints a re-seal swap and rewrites the body so the workspace gets the
placeholder back:

```python
def on_request():
    text = req_body()
    ph = placeholder()
    if not text or ph == None or ph not in text:
        return False
    req_set_body(text.replace(ph, secret()))
    return True

def on_response():
    if resp_status() != 200:
        return False
    tok = resp_json()
    if tok == None:
        return False
    access = tok.get("access_token")
    if access == None:
        return False
    mint_into_json("access_token", access, tok.get("expires_in", 3600))
    return True
```

`mint_into_json()` reads `api_hosts`/`reseal_header` from the binding params, so
the script passes only the token value and TTL; it parses the body before
registering the swap, so a non-JSON response fails closed without leaving a
dangling runtime entry.

> **Status (design-v3 phase 4).** The runtime, sandbox, and full primitive set
> are implemented: sign-family crypto (carrier `hmac_sha256` + `b64_to_hex`/
> `hex_to_b64` for multi-round signing like AWS SigV4, plus `hmac_sha256_hex`,
> `sha256_hex`, `sha1_hex`, `rs256_sign`), JWT (`jwt_encode_sign`,
> `jwt_decode_or_none`), JSON (`json_encode`, `json_decode`, and the total
> `resp_json()`), and request/response introspection — alongside the bundled
> `ovh` and `jwt-bearer` examples. Phase-4 **re-seal** has landed: the
> response-phase `mint`/`mint_into_json` primitives, the built-in
> `oauth2-reseal` scheme, and the bundled `oauth-reseal` scripted twin all ship.
> The runaway-deadline mechanism is wired and verified
> against starlark-pyo3's call-path `check_cancelled` (feature-detected); it
> activates automatically once a wheel carrying that support is published. Until
> then a non-terminating script hangs the proxy — scripts are trusted host
> config.

## See also

- [`configuration.md`](configuration.md) — the workspace config and `[[binding]]` blocks that reference injectors
- [`providers.md`](providers.md) — the provider side: where a credential's value comes from
