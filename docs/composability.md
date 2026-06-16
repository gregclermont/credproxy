# Composability — attaching credproxy to externally-managed containers

> **Status: design proposal.** Not yet implemented. This doc specifies the
> missing knobs that let credproxy ride alongside another container manager
> (devcontainers/Compose, CI runners, a hand-run proxy) instead of owning the
> whole workspace itself. It builds on the existing push model
> ([`providers.md`](providers.md)), the binding/scheme model
> ([`injectors.md`](injectors.md)), and the workspace lifecycle
> ([`workspace.md`](workspace.md)). Nothing here weakens the threat model in
> `CLAUDE.md`.

## Why

`credproxy workspace NAME start` bundles three separable concerns:

1. **proxy** — the proxy container + netns + iptables (egress capture).
2. **config** — resolve each binding's secret(s) host-side and push the wire
   config to `/admin/config` (+ CA bootstrap).
3. **workspace** — the workspace container's lifecycle (create, spec-drift,
   mounts, `setup`).

When you own all three, that bundling is convenient. To **compose** with a tool
that already owns (3) — and often (1), e.g. a Compose file that starts the proxy
as a sibling service — credproxy must be able to do (2), and discover (1),
against objects **it did not create**. Today (2) is reachable only as an
implicit step inside `start`/`apply`/`binding test` on a credproxy-managed
workspace. The knobs below expose it directly and let it target a foreign proxy.

This keeps credproxy's existing decisions intact (the push model, providers as
parent-agnostic host executables, the ephemeral-port-resolved-at-call-time rule,
the host-owned bearer token) — it just stops assuming credproxy is the one
holding the lifecycle.

## The core idea: unbundle `(bindings, proxy, state)`

A workspace **name** is really a triple, all three derived from the name:

| concern | derived from the name | unbundled knob |
|---|---|---|
| **bindings source** | `workspaces/<name>.toml` | `--bindings FILE` |
| **proxy target** | the workspace's own proxy container | `--proxy SELECTOR` / `--admin URL` |
| **state location** (auth token) | `state/workspaces/<name>/` | `--dir PATH` / `--state DIR` |

Every new command is one of these three concerns made addressable on its own.
Pass a `NAME` and you get today's behaviour (all three derived together); pass
the flags and you point each at something external. That's the whole model — the
commands are small because the idea is small.

## New & evolved commands

All live on the **strict** surface (`credproxy`): they are for automation and
integration glue, so they take explicit inputs, never prompt, and never resolve
a default workspace. `--json` is available on each. The loose surface (`credp`)
may later add cwd-derivation of the identity (see Open questions).

### `credproxy push` — resolve + POST to a proxy (foreign-capable)

```
credproxy push [NAME] [--proxy SELECTOR | --admin URL]
               [--bindings FILE] [--token FILE]
               [--wait] [--timeout SECS]
```

The first-class form of step (2). Resolves every binding's refs through its
provider (batched across bindings exactly as `start` does — see
[`providers.md`](providers.md)) and POSTs the resolved wire config to the
target's `/admin/config`, bearer-authenticated with the token.

- **Target** — `NAME` uses the workspace's own proxy; `--proxy` discovers a
  foreign container (see [Discovery selectors](#discovery-selectors)) and
  resolves its published `CREDPROXY_HTTP_PORT` at call time; `--admin URL` skips
  discovery. Port is **never cached** (per the ephemeral-port decision).
- **`--wait` / `--timeout`** — block until the proxy's **`/health`** (capture-
  ready) answers, then push. **It polls `/health`, never `/ready`** — see
  invariant **I1**. Default timeout generous enough for a slow provider unlock.
- **Lock** — credproxy holds a per-target lock (`<state>/push.lock`) so
  concurrent invocations (an integration that fires on every bring-up)
  collapse to one push. **Foreground by default** (clean exit codes,
  diagnostics); the *caller* backgrounds it with `&` if its orchestration needs
  to (invariant **I5**).
- **Atomic / fail-closed** — if any ref fails to resolve, nothing is pushed and
  the command exits nonzero naming the binding (same contract as `binding
  test`). A partial config is never sent (invariant **I3**).

`start`/`apply` keep their current behaviour by calling this same engine
internally — `push` is the extraction, not a parallel path.

### `credproxy resolve` — resolve to a config blob, no proxy contact

```
credproxy resolve [NAME] [--bindings FILE] (--json | --out FILE)
```

Step (2) without the POST: emit the resolved wire config. This is the
delivery-at-creation channel — the integration hands the blob to the proxy at
container creation instead of pushing after.

- `--json` writes the blob to stdout (RAM-only on the host; capture it into an
  env var for a Compose `environment`-sourced secret).
- `--out FILE` writes it to a file (for a Compose `file:`-sourced secret or a
  bind mount). **This is the at-rest variant** — see invariant **I4** for
  placement rules and why `--json`/push are preferred.

Generalises the existing ad-hoc `binding test --provider … --secret …`
(which dry-runs a single definition) to "resolve a whole binding set to wire
form."

### `credproxy init` — provision host state without creating a container

```
credproxy init (NAME | --dir PATH) [--print-state-dir] [--print-env]
```

Ensures the host-owned bearer token exists for an identity, decoupled from
container creation, so it is present **before** an external manager mounts it.
Idempotent.

- `--dir PATH` keys state off a directory (the integration's project dir) rather
  than a credproxy workspace name — the identity an external tool actually has.
- `--print-state-dir` prints the resolved state dir.
- `--print-env` emits `KEY=VALUE` lines (`CREDPROXY_STATE`, `CREDPROXY_TOKEN…`)
  for the caller to route. This is the only way a pre-create host hook can hand
  values to the manager (e.g. a Compose `.env`), because such hooks cannot
  export env into the manager's process. credproxy stays parent-agnostic by
  emitting generic env — *what file it lands in is the caller's choice*.

### `credproxy state-dir` — print the state dir (read-only companion to `init`)

```
credproxy state-dir (NAME | --dir PATH)
```

### Integration scaffolding: `credproxy emit-compose` (optional)

```
credproxy emit-compose [--image TAG]
```

Emits the proxy **Compose service** (cap, tmpfs, token mount, published port,
healthcheck wired to `/ready`) plus the two workspace-service lines
(`network_mode: service:proxy`, `depends_on: { proxy: service_healthy }`). Pure
convenience: it keeps the service definition in sync with the image's `ENV`
contract (the same single-source-of-truth `docker inspect Config.Env` trick the
CLI already uses), so an integration doesn't hand-maintain ports/paths. The one
deliberately Compose-aware command; everything else is parent-agnostic. You can
always hand-write the service instead.

### Future: `credproxy daemon`

A host process watching `docker events` for a proxy container appearing (matched
by image/label) and running `push --wait` against it automatically, reading the
binding set from a label the proxy carries. This is the clean replacement for an
integration backgrounding `push` from a pre-create hook: properly lifecycle-
managed (no orphaned background process, no per-bring-up lock dance), and it
serves every parent identically. It is the daemon `CLAUDE.md` already anticipates
under the provider protocol ("today the CLI execs it; a future daemon could").
It **reuses `push --wait` verbatim** — build the command first, the daemon is a
watcher around it. Out of scope for the first cut; listed so the commands above
are designed to be daemon-drivable from day one.

## Proxy API: two readiness signals

Egress-capture readiness and config readiness have different owners and
lifetimes, so they are **two signals**, never one (invariant **I2**):

| endpoint | green when | consumed by |
|---|---|---|
| `/health` | process up **and iptables installed and listeners bound** (capture-ready; creds-agnostic) | `start`, `push --wait`, any liveness probe |
| `/ready` | `/health` **and** a non-empty config has been pushed (creds-ready) | an external health-gate (Compose `depends_on: service_healthy`) |

`/health`'s "iptables installed" clause is load-bearing: the proxy entrypoint
must install rules **before** `/health` goes green, or "healthy" gates nothing
(no un-captured window). `/ready` lets an external manager hold a dependent
container until creds are actually in — the barrier becomes the manager's
existing dependency mechanism, with **no credproxy code in the dependent
container** (it keeps the user's image pristine, per "BYO image, never
modified").

The inward `/setup` endpoint additionally gains an optional `config_generation`
counter, so a consumer that prefers to poll readiness *from inside* the
workspace (rather than via the manager's health-gate) can, without exposing any
secret value (least-disclosure unchanged).

## Discovery selectors

`--proxy` stays generic so credproxy never learns what a "devcontainer" is. The
caller supplies the selector; credproxy resolves a container → published port:

- `--admin URL` — explicit, no discovery.
- `--container NAME|ID` — a docker container.
- `--discover LABEL=VALUE[,LABEL=VALUE]` — first container matching all labels.
- `--compose-project NAME` — sugar for
  `--discover com.docker.compose.project=NAME,com.docker.compose.service=proxy`.
  The single bit of Compose awareness, clearly delimited.

## Integration patterns

How the knobs combine. The first is canonical; the rest are alternatives with
different trade-offs.

### A. Compose health-gated sidecar (recommended)

The proxy is a Compose service; the workspace shares its netns and gates on it.

1. The manager's **pre-create host hook** runs `credproxy init --dir "$PWD"
   --print-env > .env` (token + `CREDPROXY_STATE` for Compose interpolation) and
   backgrounds `credproxy push --compose-project "$P" --wait &`.
2. Compose brings up the proxy; its **healthcheck probes `/ready`**, so it
   reports healthy only once the backgrounded `push` lands.
3. The workspace service `depends_on: { proxy: service_healthy }` — so it does
   not start until the proxy is **captured + credentialed**.

`devcontainer up` (or `docker compose up`) returning thus means "ready". The
only integration-owned policy is the `&` (background the push) and the `.env`
bridge; all mechanics are credproxy's. A worked end-to-end sketch targets
[claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer)
(Compose mode: proxy service + `network_mode: service:proxy` workspace).

### B. Deliver-at-creation (file or env secret)

Skip the push: `credproxy resolve` produces the blob, the manager mounts it at
proxy startup.

- **env-sourced** (host-transient): `export CREDPROXY_CONFIG="$(credproxy
  resolve --bindings F --json)"` then a Compose `environment`-sourced secret —
  no host file, secret lives only in the bring-up process env and the proxy's
  tmpfs.
- **file-sourced** (at-rest): `credproxy resolve --out <state>/config.json` then
  a Compose `file:` secret / bind mount.

Trade-off: config is **baked at creation** — no live `apply`/rotation; a binding
change means re-create. Prefer A unless a no-push, no-wrapper flow is required
(see I4). The file variant is the only one that works with **no wrapper at all**
(a pre-create hook can write a file but cannot export env), at the cost of an
at-rest secret.

### C. Generic / hand-run / CI

Proxy started however (a bare `docker run`, a CI service container):
`credproxy push --admin http://127.0.0.1:$PORT --bindings ./creds.toml --wait`.

### D. Daemon (future)

`credproxy daemon` running; the manager only needs `init`. The push happens
reactively when the proxy appears. Removes the `&` from pattern A.

## Invariants — do not reverse

- **I1 — `--wait` polls `/health`, never `/ready`.** `/ready` is gated on the
  very push that `--wait` precedes; waiting on it deadlocks
  (`push → ready → creds → push`). "Wait for the proxy" means wait for the
  **listener to accept**, not for the health-gate to open.
- **I2 — two readiness signals.** Never collapse `/health` into requiring creds:
  credproxy's own `start` waits on `/health` *then* pushes, so a creds-gated
  `/health` would deadlock standalone start the same way. `/health` =
  capture-ready; `/ready` = creds-ready.
- **I3 — push is atomic and fail-closed.** All refs resolve or nothing is sent;
  exit nonzero naming the failure. Under an external health-gate this surfaces as
  the proxy staying unhealthy (so the bring-up fails closed) — keep clean
  diagnostics on the command itself for the cases that can read them.
- **I4 — secrets posture: transient by default.** The default path keeps secrets
  to RAM + authenticated transit + the proxy's tmpfs (`push`, `resolve --json`).
  `resolve --out FILE` is the at-rest escape hatch: write **0600**, under the
  state dir, **never in the repo / `.devcontainer`** (where it could be
  committed), and treat it as session-lived. Prefer push or the env-source.
  Same-user read access is already out of scope; the loss the file incurs is
  *transience* (defense-in-depth), nothing more — but it is a real loss.
- **I5 — parent-agnostic boundary.** credproxy provides **mechanics** (discover,
  wait-for-listen, resolve, lock, push); the integration owns **orchestration
  policy** (when to invoke, whether to background, lifecycle). Discovery
  selectors are generic; `--compose-project`/`emit-compose` are the only Compose-
  aware sugar and are clearly delimited. Don't bake "race a Compose bring-up"
  into the core.
- **I6 — port resolved at call time.** `--proxy`/`--container`/`--discover`
  resolve the published port per invocation; never persist it. (Existing
  decision, restated for the foreign case.)
- **I7 — CA trust is pulled, not pushed.** credproxy exposes its CA over the open
  bootstrap route (`proxy.local`); the consumer's own `setup`/`postCreate`
  installs it. credproxy does **not** reach into a foreign container's trust
  store — that would couple it to every image's CA layout. An optional
  `bootstrap-ca <container>` for common stores may come later as sugar, but the
  pull model is the default and keeps the boundary clean.

## Surfaces & flags

| command | surface | `--json` | foreign target | mutates host |
|---|---|---|---|---|
| `push` | strict | yes | `--proxy`/`--admin` | no (writes lock only) |
| `resolve` | strict | yes (`--json`) | n/a | only with `--out` |
| `init` | strict | yes | n/a (`--dir`) | token + state dir |
| `state-dir` | strict | yes | n/a | no |
| `emit-compose` | strict | n/a (emits YAML) | n/a | no |
| `daemon` (future) | strict | n/a | watches all | no |

## Open questions

- **Command placement.** Top-level verbs (`push`/`resolve`/`init`/`state-dir`)
  as proposed, vs. a `credproxy proxy …` / `credproxy attach …` noun group. Top-
  level reads naturally and matches the "extracted step" framing; a noun group
  groups the foreign workflow. Leaning top-level.
- **cwd-addressing interplay.** Should the loose surface let `init`/`push`
  derive the identity from cwd (the directory→workspace resolver discussed for
  `credp`)? Strict stays explicit regardless.
- **`resolve --out` at all?** Given I4, is the file variant worth shipping, or
  ship only `--json` (env-source) + push and refuse to make at-rest easy? It is
  the *only* zero-wrapper option for managers without a host post-up hook, which
  argues for keeping it — with the placement guardrails.
- **Daemon scope.** How the daemon maps a discovered proxy → its binding set (a
  label carrying a host path vs. a registry), and how it authenticates per
  target. Deferred with the daemon itself.
- **`emit-compose` reach.** How much Compose-specific scaffolding belongs in the
  engine vs. an integration's own template. Currently minimal by intent.
- **CA into foreign images (I7).** Keep pull-only (recommended) or add
  `bootstrap-ca` sugar for the common trust stores.
</content>
</invoke>
