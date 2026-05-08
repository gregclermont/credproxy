# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

This repo currently contains only `design.md` — no code, build system, tests, or CI exist yet. The product (a transparent egress proxy for sandbox containers, codename "myproxy" / credproxy) is in design phase. Read `design.md` end-to-end before making any architectural decisions; it is the authoritative spec for v1.

When implementation begins, the v1 deliverables enumerated in `design.md` ("V1 deliverables" section) are the scope. Don't expand scope beyond that list without surfacing the tradeoff.

## Big-picture architecture

The product is **two pieces that must stay separated**:

1. **Sidecar container** (Linux, requires `NET_ADMIN`): owns the netns, installs iptables rules, runs mitmproxy on `127.0.0.1:39999`, hosts a Python addon (~200 lines) that does bootstrap endpoints + SNI gating + credential injection.
2. **Host CLI** (Python in v1, Go later): a thin orchestrator over `docker`/`podman`. Configures and launches the sidecar; runs agent containers with `--network=container:<sidecar>` to share the netns.

The agent container is **the user's** image — never modified, never granted privilege. This "bring your own image" constraint is load-bearing for the whole design.

Traffic flow: agent egress → iptables OUTPUT in shared netns → REDIRECT to mitmproxy → SNI peek → either inject-and-forward (terminate TLS) or passthrough (`client_hello.ignore_connection = True`).

## Architecture decisions that should not be casually reversed

These are spelled out in `design.md` ("Architecture decisions worth preserving") but worth surfacing because they will tempt reconsideration:

- **Two-container shape is forced**, not chosen — netfilter must run in the same kernel as the traffic, and on macOS/Windows that kernel is inside Docker Desktop's VM. A host process cannot install iptables there. Don't propose collapsing to a single host process.
- **Transparent capture of all TCP**, not port-based selection. The product promise is "every tool works"; selective capture leaks edge cases.
- **SNI-based intercept decision**, not IP-based. CDN IP reuse breaks IP rules.
- **HTTP/3 dropped at netfilter** to force TCP fallback, not intercepted. mitmproxy QUIC is experimental.
- **IPv6 dropped entirely in v1.**
- **Bootstrap over plain HTTP from inside the netns is fine** — no eavesdropper exists on shared loopback/link-local. This resolves the chicken-and-egg of trusting the trust source. Don't add TLS or auth to the bootstrap endpoint.
- **Credential lookup must go through an interface** that can be swapped for IPC to a host plugin later. Don't hard-code direct config-file reads inside the inject path; the future host-plugin system is informing the v1 design.
- **Sidecar holds proxy core; host plugins (future) handle host-touchy things.** Don't push host-touchy logic into the sidecar to "simplify"; it breaks cross-platform.

## v1 non-goals (don't accidentally implement)

- HTTP/3/QUIC interception, IPv6, DNS interception, hostname-based egress allowlisting, process attribution (PID), cert-pinning workarounds, mTLS injection, multi-sandbox-per-sidecar, bypass-resistance against an adversarial sandbox. v1 is a developer convenience boundary, not a hardened jail.

## Key constants (from `design.md`)

- `MITMPROXY_UID=31337` — mitmproxy runs as this uid; the iptables `-m owner --uid-owner` rule depends on it (prevents redirect loop on mitmproxy's own outbound).
- `PROXY_PORT=39999` — transparent-intercept bind port. Picked unusual to minimize collision with sandbox-side dev tools. The one port unavailable to the agent on `0.0.0.0`/`127.0.0.1`.
- `SENTINEL_IP=169.254.1.1` — link-local for the bootstrap endpoint, resolved as `proxy.local` from the agent side. The addon recognizes flows targeting this IP via `SO_ORIGINAL_DST` and synthesizes responses (does not forward upstream).

## Commands

None yet — no build, lint, or test commands exist. When implementation lands, update this section with the actual commands. Do not invent placeholders.

## Open design questions

`design.md` ends with an "Open questions" section (bootstrap env-var persistence, discovery URL convention, config reload mechanism, `/llms.txt` format, per-request vs. per-host injection, CA delivery via volume mount). These are unresolved — surface them rather than picking silently if your work touches one.
