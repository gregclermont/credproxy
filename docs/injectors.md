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
| `sigv4` | `sigv4` | — | none (sign family) | none |

A `sigv4` binding uses a multi-slot secret, e.g.:

```sh
credproxy workspace NAME binding add --injector sigv4 --provider env \
    --secret access_key_id=AWS_ACCESS_KEY_ID \
    --secret secret_access_key=AWS_SECRET_ACCESS_KEY \
    --host sts.amazonaws.com
```

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

## See also

- [`configuration.md`](configuration.md) — the workspace config and `[[binding]]` blocks that reference injectors
- [`providers.md`](providers.md) — the provider side: where a credential's value comes from
