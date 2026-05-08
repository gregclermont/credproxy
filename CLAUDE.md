# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

The product (codename "credproxy") is a transparent egress proxy for workspace containers — LLM-agent sandboxes, CI runners, dev shells, batch jobs. `design.md` is the v1 spec; read it before making architectural decisions. The repo also contains a working v0 dev harness under `proxy/` plus a `Makefile` and `docs/workspace.md`.

When implementation continues, the v1 deliverables enumerated in `design.md` ("V1 deliverables" section) are the scope. Don't expand scope beyond that list without surfacing the tradeoff.

## Big-picture architecture

The product is **two containers that must stay separated**:

1. **Proxy container** (Linux, requires `NET_ADMIN`): owns the netns, installs iptables rules, runs mitmproxy on `127.0.0.1:39999`, plus a small aiohttp app on `127.0.0.1:39998` for the bootstrap API. iptables redirects sentinel-IP `:80` to the bootstrap listener and everything-else-TCP to mitmproxy.
2. **Host CLI** (Python in v1, Go later): a thin orchestrator over `docker`/`podman`. Configures and launches the proxy; runs workspace containers with `--network=container:<proxy>` to share the netns.

The workspace container is **the user's** image — never modified, never granted privilege. This "bring your own image" constraint is load-bearing for the whole design. See `docs/workspace.md` for the constraints joining the proxy's netns imposes.

Traffic flow: workspace egress → iptables OUTPUT in shared netns → REDIRECT to mitmproxy (or to bootstrap for sentinel:80) → SNI peek → either inject-and-forward (terminate TLS) or passthrough (`client_hello.ignore_connection = True`).

## Architecture decisions that should not be casually reversed

These are spelled out in `design.md` ("Architecture decisions worth preserving") but worth surfacing because they will tempt reconsideration:

- **Two-container shape is forced**, not chosen — netfilter must run in the same kernel as the traffic, and on macOS/Windows that kernel is inside Docker Desktop's VM. A host process cannot install iptables there. Don't propose collapsing to a single host process.
- **Transparent capture of all TCP**, not port-based selection. The product promise is "every tool works"; selective capture leaks edge cases.
- **SNI-based intercept decision**, not IP-based. CDN IP reuse breaks IP rules.
- **HTTP/3 dropped at netfilter** to force TCP fallback, not intercepted. mitmproxy QUIC is experimental.
- **IPv6 dropped entirely in v1.**
- **Bootstrap over plain HTTP from inside the netns is fine** — no eavesdropper exists on shared loopback/link-local. This resolves the chicken-and-egg of trusting the trust source. Don't add TLS or auth to the bootstrap endpoint.
- **Credential lookup must go through an interface** that can be swapped for IPC to a host plugin later. Don't hard-code direct config-file reads inside the inject path; the future host-plugin system is informing the v1 design.
- **Proxy container holds the proxy core; host plugins (future) handle host-touchy things.** Don't push host-touchy logic into the proxy to "simplify"; it breaks cross-platform.

## v1 non-goals (don't accidentally implement)

- HTTP/3/QUIC interception, IPv6, DNS interception, hostname-based egress allowlisting, process attribution (PID), cert-pinning workarounds, mTLS injection, multi-workspace-per-proxy, bypass-resistance against an adversarial workspace. v1 is a developer convenience boundary, not a hardened jail.

## Key constants

- `MITMPROXY_UID=31337` — mitmproxy runs as this uid; the iptables `-m owner --uid-owner` rule depends on it (prevents redirect loop on mitmproxy's own outbound).
- `PROXY_PORT=39999` — mitmproxy transparent-intercept bind port. Picked unusual to minimize collision with workspace-side dev tools.
- `BOOTSTRAP_PORT=39998` — aiohttp bootstrap-API bind port. Same "unusual" reasoning, adjacent to `PROXY_PORT` so the pair is easy to remember.
- `SENTINEL_IP=169.254.1.1` — link-local for the bootstrap endpoint, resolved as `proxy.local` from the workspace side. iptables redirects `<sentinel>:80` to the bootstrap listener.

## Commands

- `make build` — build the proxy image.
- `make up` / `make down` / `make restart` — lifecycle.
- `make logs` — tail proxy logs.
- `make reload` — hot-reload python code in the running proxy (kills the python child; the bash supervisor respawns it).
- `make shell` — root shell inside the proxy.
- `make workspace` — run an interactive workspace container joined to the proxy netns.
- `make rebuild` — `down + build + up`.

## Open design questions

`design.md` ends with an "Open questions" section (bootstrap env-var persistence, discovery URL convention, config reload mechanism, `/llms.txt` format, per-request vs. per-host injection, CA delivery via volume mount). These are unresolved — surface them rather than picking silently if your work touches one.
