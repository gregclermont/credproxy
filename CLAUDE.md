# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

The product (codename "credproxy") is a transparent egress proxy for workspace containers — LLM-agent sandboxes, CI runners, dev shells, batch jobs. `design-v0.md` is the *initial* design sketch — useful background, but the implementation has diverged in places and that's fine; learn-by-building is expected. CLAUDE.md (this file) and the code are the living source of truth. The repo also contains a working dev harness under `proxy/` plus a `Makefile` and `docs/workspace.md`.

When implementation continues, the v1 deliverables enumerated in `design-v0.md` ("V1 deliverables" section) are a reasonable starting scope, but treat the list as a starting point rather than a contract. Surface tradeoffs when scope shifts.

## Big-picture architecture

The product is **two containers that must stay separated**:

1. **Proxy container** (Linux, requires `NET_ADMIN`): owns the netns, installs iptables rules, runs two listeners — mitmproxy on `127.0.0.1:39999` (transparent intercept) and a single aiohttp HTTP API on `0.0.0.0:39998` that serves both workspace-facing bootstrap routes and host-facing admin routes. iptables redirects sentinel-IP `:80` to the HTTP listener and everything-else-TCP to mitmproxy. The HTTP listener is port-published to the host as `127.0.0.1:39998`; workspace reaches it through the sentinel redirect or directly via `127.0.0.1:39998` in the shared netns.
2. **Host CLI** (`bin/credproxy`, Python; Go later): orchestrator-like role. Today it has one subcommand, `push-config`, that reads a YAML config, resolves `${secret:NAME}` against host env vars, and POSTs the resolved JSON to `/admin/config`. The Makefile wraps this as `make set-config`.

The workspace container is **the user's** image — never modified, never granted privilege. This "bring your own image" constraint is load-bearing for the whole design. See `docs/workspace.md` for the constraints joining the proxy's netns imposes.

Traffic flow: workspace egress → iptables OUTPUT in shared netns → REDIRECT to mitmproxy (or to the HTTP API for sentinel:80) → SNI peek → either substitute-placeholder-and-forward (terminate TLS) or passthrough (`client_hello.ignore_connection = True`).

**Configuration flow**: `make up` generates `.run/auth.token` (mode 0600) on the host if absent, then bind-mounts it read-only into the proxy at `/run/secrets-ro/auth.token`. The entrypoint stages it onto tmpfs at `/run/secrets/auth.token` (mode 0400, owned by uid 31337); the python process reads it at startup and exits if missing. Config lives on tmpfs at `/run/secrets/config.json`, written by `POST /admin/config`. Lifecycle: the token survives both python respawn and full container restart (host-owned); config survives python respawn only — the host CLI re-pushes after a container restart. A 401 on push means the host file changed after the container started; recovery is `make restart`.

## Threat model (v1)

- **Workspace container**: cannot read the host filesystem, so cannot read `.run/auth.token`. Can hit `/admin/*` endpoints over the shared netns and gets 401 without the token. No window in which `/admin/config` is unauthenticated.
- **Browser on host**: blocked by Chrome's Private Network Access (we never set `Access-Control-Allow-Private-Network`) plus the `fetch_metadata_guard` middleware (rejects requests with `Sec-Fetch-Site: cross-site`/`same-site`). Both layers act before any handler runs.
- **Other host users on a multi-user host**: can read `.run/auth.token` only if FS perms permit (mode 0600 keeps it out of reach of other users in the normal case). Damage ceiling is DoS-or-config-replace — the user's secrets live in op://, keychain, etc., and only enter the proxy through bearer-authenticated `push-config` calls. Documented limitation; v1 is a single-user dev workstation tool.
- **Same-user malicious process**: out of scope (already has access to ssh keys, env vars, etc.).

## Architecture decisions that should not be casually reversed

These were spelled out in `design-v0.md` ("Architecture decisions worth preserving") and still apply — worth surfacing because they will tempt reconsideration:

- **Two-container shape is forced**, not chosen — netfilter must run in the same kernel as the traffic, and on macOS/Windows that kernel is inside Docker Desktop's VM. A host process cannot install iptables there. Don't propose collapsing to a single host process.
- **Transparent capture of all TCP**, not port-based selection. The product promise is "every tool works"; selective capture leaks edge cases.
- **SNI-based intercept decision**, not IP-based. CDN IP reuse breaks IP rules.
- **HTTP/3 dropped at netfilter** to force TCP fallback, not intercepted. mitmproxy QUIC is experimental.
- **IPv6 dropped entirely in v1.**
- **Bootstrap over plain HTTP from inside the netns is fine** — no eavesdropper exists on shared loopback/link-local. This resolves the chicken-and-egg of trusting the trust source. Don't add TLS or auth to the bootstrap routes.
- **Single HTTP listener for admin + bootstrap.** Bearer auth gates `/admin/*`; bootstrap routes are open. Browsers are kept out by PNA + Sec-Fetch-Site, not by a separate listener or a separate iptables rule. Don't re-split.
- **Host-owned bearer, bind-mounted into the proxy.** `.run/auth.token` is the source of truth; the proxy reads a tmpfs copy staged by entrypoint. No first-call ceremony, no race window; container restart preserves auth. Don't reintroduce TOFU or in-container token generation.
- **Credential lookup must go through an interface** that can be swapped for IPC to a host plugin later. Don't hard-code direct config-file reads inside the inject path; the future host-plugin system is informing the v1 design.
- **Proxy container holds the proxy core; host plugins (future) handle host-touchy things.** Don't push host-touchy logic into the proxy to "simplify"; it breaks cross-platform.

## v1 non-goals (don't accidentally implement)

- HTTP/3/QUIC interception, IPv6, DNS interception, hostname-based egress allowlisting, process attribution (PID), cert-pinning workarounds, mTLS injection, multi-workspace-per-proxy, bypass-resistance against an adversarial workspace. v1 is a developer convenience boundary, not a hardened jail.
- Multi-user host support: documented limitation, not a feature.

## Key constants

- `MITMPROXY_UID=31337` — mitmproxy runs as this uid; the iptables `-m owner --uid-owner` rule depends on it (prevents redirect loop on mitmproxy's own outbound).
- `PROXY_PORT=39999` — mitmproxy transparent-intercept bind port. Picked unusual to minimize collision with workspace-side dev tools.
- `HTTP_PORT=39998` — merged HTTP API bind port (admin + bootstrap). Bound on `0.0.0.0` inside the netns and port-published to host as `127.0.0.1:39998`.
- `SENTINEL_IP=169.254.1.1` — link-local for the workspace-facing endpoint, resolved as `proxy.local` from the workspace side. iptables redirects `<sentinel>:80` to `HTTP_PORT`.

## Commands

- `make build` — build the proxy image.
- `make up` / `make down` / `make restart` — lifecycle. `make up` generates `.run/auth.token` if absent, then starts the proxy with that token bind-mounted. Config is empty until `make set-config`.
- `make set-config` — resolve `proxy/config.yaml` `${secret:NAME}` refs from host env and POST via `/admin/config`. e.g. `GITHUB_PAT=$(op read 'op://...') make set-config`.
- `make logs` — tail proxy logs.
- `make reload` — hot-reload python code in the running proxy (kills the python child; the bash supervisor respawns it; state survives via tmpfs).
- `make shell` — root shell inside the proxy.
- `make workspace` — run an interactive workspace container joined to the proxy netns.
- `make rebuild` — `down + build + up`.
- `make test` — run pytest in the proxy image.

## Open design questions

Surface these rather than picking silently if your work touches one:

- **`/llms.txt` format.** Currently free-form prose; structured/AGENTS.md-style alternatives haven't been evaluated.
- **Per-request vs. per-host injection.** Currently strictly per-host; no path/method matching.
