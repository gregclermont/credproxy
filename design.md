# Sandbox Egress Proxy — Design Document

## Summary

A transparent egress proxy for developer sandbox containers (especially LLM-agent
sandboxes) that performs HTTPS credential injection for a configured set of
hostnames, while passing all other traffic through unmodified. Designed to work
with any agent container image and on any major workstation OS (Linux, macOS,
Windows via Docker Desktop).

The product ships as two pieces:

1. A **sidecar container** that owns the network namespace, runs mitmproxy, and
   does all the netfilter setup.
2. A **host CLI** (Python in v1, Go later) that orchestrates the sidecar and
   the agent container.

## Motivation

LLM agents and dev sandboxes need to reach external APIs (GitHub, package
registries, model providers, etc.) using credentials. Two recurring problems:

- **Credentials should not be visible to the agent itself.** A sandbox should be
  able to grant access without exposing the secret token to whatever code runs
  inside it.
- **Tools don't reliably honor `HTTP_PROXY` env vars.** Anything claiming to
  "support every tool" needs transparent capture, not opt-in proxying.

This proxy solves both: it captures all egress at the kernel level and rewrites
HTTPS requests in flight to add an `Authorization` header (or similar) for
configured hostnames. The sandbox never sees the secret.

## Goals

- **Transparent capture** of all TCP egress from the agent container.
- **Credential injection** for HTTPS requests to a configured allowlist of
  hostnames.
- **"Bring your own image."** Users supply any agent image; the only required
  integration step is one container flag.
- **Cross-platform** on Linux, macOS, and Windows (Docker Desktop, Podman).
- **Forward-compatible** with a future host-process / plugin system for richer
  integrations (password managers, OS keychains, approval UIs).

## Non-goals (v1)

- HTTP/3 / QUIC interception. Dropped at netfilter; clients fall back to TCP.
- IPv6 support. Dropped entirely in the sandbox netns.
- DNS interception or hostname-based egress allowlisting. Different feature.
- Process attribution (which PID inside the sandbox originated a request).
  Different feature; would require eBPF.
- Workarounds for cert pinning, mTLS, ECH. Documented as supported alternatives.
- Multi-sandbox shared sidecar. v1 = one sidecar per sandbox.
- Bypass-resistance against a sandbox that's *trying* to escape. v1 is a
  developer convenience boundary, not a hardened jail.

## Architecture

```
┌─ sidecar container (NET_ADMIN) ──────────────────┐
│  iptables/ip6tables setup in own netns           │
│  mitmproxy on 127.0.0.1:39999                    │
│  addon: bootstrap endpoints + SNI gate + inject  │
│  config: /etc/proxy/config.yaml (mounted)        │
└──────────────────┬───────────────────────────────┘
                   │ shared netns
┌─── agent container (any image) ──────────────────┐
│  joined via --network=container:<sidecar>        │
│  no NET_ADMIN, no image changes required         │
└──────────────────────────────────────────────────┘

         orchestrated by → host CLI (Python in v1)
```

### Why two containers

The architecture is *forced*, not chosen, by three constraints:

1. **Netfilter must run in the same Linux kernel as the traffic.** On macOS and
   Windows, containers run inside Docker Desktop's hidden Linux VM. A host
   process on those OSes cannot manipulate that VM's iptables. The only way to
   get netfilter rules in the same kernel as the sandbox is to run a container
   in that same VM.
2. **The sandbox should be unprivileged and unmodified.** Putting `NET_ADMIN`
   on the agent container means users have to add a flag to every run; putting
   iptables setup in the agent image means modifying every supported image.
   Both violate "bring your own image."
3. **Transparent intercept needs a port to redirect to and a process listening
   there.** That process is mitmproxy, which is happiest sitting alongside the
   netfilter rules in the same netns.

The sidecar resolves all three: it owns the netns and the netfilter rules,
hosts mitmproxy, and the agent container joins via shared netns without any
elevated privilege of its own.

### Why mitmproxy

- Production-quality HTTP/1, HTTP/2, HTTP/3, WebSocket, raw TCP, raw UDP, and
  DNS support.
- Native SNI peeking and TLS passthrough (the `next_layer` / `tls_clienthello`
  hooks). Exactly the primitive the v1 design relies on.
- Python addon API is small and well-documented; the entire v1 addon is
  ~200 lines.
- Don't reinvent it.

## Components

### Sidecar image

Contents:

- Linux base (Alpine or `debian:slim`).
- `mitmproxy` (pip-installed).
- `iptables`, `ip6tables`, `iproute2` (for `ip addr add`).
- One Python addon file (`/opt/proxy/addon.py`).
- One entrypoint shell script (`/opt/proxy/entrypoint.sh`).

The entrypoint runs as root briefly to install iptables rules, then drops to a
dedicated unprivileged uid (`31337`) and execs mitmproxy.

Required Linux capability: `NET_ADMIN` only.

### iptables rules

Variables (set in entrypoint):

- `MITMPROXY_UID=31337` — uid mitmproxy runs as. Picked unusual to avoid
  collision with the agent image's user uid.
- `PROXY_PORT=39999` — port mitmproxy binds for transparent intercept. Picked
  high and unusual to minimize collision with sandbox-side dev tools.
- `SENTINEL_IP=169.254.1.1` — link-local address used for the bootstrap
  endpoint (resolved as `proxy.local` from the agent side).

Setup, in order:

```sh
# Bind sentinel address; creates implicit route via lo.
ip addr add 169.254.1.1/32 dev lo

# nat OUTPUT: redirect logic. Order matters.
# 1. Don't loop mitmproxy's own outbound back into itself.
iptables -t nat -A OUTPUT -m owner --uid-owner 31337 -j RETURN
# 2. Don't touch sandbox-internal loopback (sandbox-local services keep working).
#    Matches by destination, not interface, so traffic to the sentinel is NOT
#    exempted (sentinel is 169.254.x.y, not 127.x.x.x).
iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
# 3. Send everything else to mitmproxy.
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 39999

# filter OUTPUT: drops.
# Force HTTP/3 → TCP fallback by killing QUIC.
iptables -A OUTPUT -p udp --dport 443 -j DROP

# IPv6: not supported in v1; drop everything.
ip6tables -P OUTPUT  DROP
ip6tables -P INPUT   DROP
ip6tables -P FORWARD DROP
```

Notes:

- No PREROUTING rules. Shared netns means all sandbox egress is locally
  generated, so OUTPUT covers the whole picture.
- DNS (UDP/53) is left alone. The system resolver works normally.
- ICMP is left alone (default policy ACCEPT). Optional extra DROP rule for
  stricter sandboxes.
- No cleanup needed: the netns dies when the sidecar container stops.

### mitmproxy and addon

mitmproxy runs in transparent mode bound to `127.0.0.1:39999`, with PROXY
protocol disabled (we use `SO_ORIGINAL_DST` for original destination recovery,
not PROXY).

The addon has three responsibilities:

#### 1. Bootstrap endpoint synthesis

For any incoming flow whose original destination (via `SO_ORIGINAL_DST`) is
the sentinel IP, synthesize HTTP responses from the addon directly — do not
forward upstream.

Endpoints:

| Path             | Method | Returns                                              |
|------------------|--------|------------------------------------------------------|
| `/ca.crt`        | GET    | CA certificate (PEM)                                 |
| `/bootstrap.sh`  | GET    | Shell script: write CA to disk, export env vars      |
| `/env.sh`        | GET    | Just the env-var exports (for `eval $(curl …)`)      |
| `/setup`         | GET    | JSON: ca_url, env vars to set, install hints         |
| `/llms.txt`      | GET    | Plain-text instructions for an LLM agent             |
| `/domains`       | GET    | JSON: list of inject hosts and disposition           |
| `/health`        | GET    | JSON: `{ok: true, version: "…"}`                     |

No authentication in v1. Plain HTTP is acceptable because the bootstrap
endpoint is on the shared loopback / link-local of the netns; nobody else can
intercept it.

#### 2. SNI-based passthrough vs. interception

For all other connections (real upstream traffic), use mitmproxy's
`tls_clienthello` hook:

- Read SNI from the ClientHello.
- If SNI is in the inject list → terminate TLS in mitmproxy (so the addon can
  see and modify the request).
- Otherwise → set `client_hello.ignore_connection = True` to enter TLS
  passthrough mode (forward bytes blindly to the original destination).

For non-TLS TCP (plain HTTP, raw protocols), default behavior is passthrough.
v1 does not inject into plain HTTP (no use case, and a pinned-cert detection
moot).

#### 3. Credential injection

For terminated TLS flows, on each HTTP request:

- Look up the request's `Host` / HTTP/2 `:authority` against the inject map.
  Match per-request, not per-connection — HTTP/2 connection coalescing can
  multiplex multiple hosts on one TLS session.
- If the host has an inject entry and the configured header is not already
  present, add it.
- Idempotent: skip if the header is already set (don't double-inject when a
  caller already has its own auth).

### Configuration

Single YAML file at `/etc/proxy/config.yaml` (mounted into the sidecar):

```yaml
inject:
  api.github.com:
    header: Authorization
    value: "Bearer ghp_..."
  api.openai.com:
    header: Authorization
    value: "Bearer sk-..."
```

Schema (v1):

- `inject`: map of `hostname` → injection spec.
- Each spec: `header` (name) and `value` (literal string).

Reserved for future versions:

- `value: "@op://vault/item/field"` — credential reference resolved by a host
  plugin.
- `headers: [...]` — multiple headers per host.
- `condition:` block — restrict by path, method, etc.
- `tls_pin:` — accept a specific upstream cert hash (for stricter passthrough
  decisions).

### Host CLI (Python v1)

A thin orchestrator over `docker` / `podman`. Commands:

| Command                         | Behavior                                              |
|---------------------------------|-------------------------------------------------------|
| `myproxy start`                 | `docker run -d --cap-add NET_ADMIN -v config:... <sidecar-image>` |
| `myproxy stop`                  | Stop and remove the sidecar container                 |
| `myproxy status`                | Print sidecar state, current inject hosts             |
| `myproxy run --image X -- CMD`  | Run an agent container joined to the sidecar's netns  |
| `myproxy webui`                 | Port-forward mitmproxy's webUI from sidecar to host   |
| `myproxy logs`                  | Tail sidecar logs                                     |

Configuration discovery:
- `~/.config/myproxy/config.yaml` (Linux/macOS)
- `%APPDATA%\myproxy\config.yaml` (Windows)

State: none persistent beyond config. Sidecar container is the only runtime
artifact.

Implementation: ~200–400 lines of Python, no heavyweight dependencies.
Designed to be rewritten in Go later without changing the user-visible CLI
contract.

## Bootstrap flow

The agent container starts with no TLS trust for the proxy. The first thing
that runs in the sandbox should bootstrap trust:

```sh
curl -s http://proxy.local/bootstrap.sh | sh
```

Or, equivalently, sourcing the env-only form:

```sh
eval "$(curl -s http://proxy.local/env.sh)"
```

`bootstrap.sh` (illustrative; served by the addon):

```sh
#!/bin/sh
set -eu
CA_PATH=/tmp/proxy-ca.crt
curl -sf -o "$CA_PATH" http://proxy.local/ca.crt

# Export env vars in the current shell.
export SSL_CERT_FILE="$CA_PATH"
export REQUESTS_CA_BUNDLE="$CA_PATH"
export NODE_EXTRA_CA_CERTS="$CA_PATH"
export GIT_SSL_CAINFO="$CA_PATH"
export CARGO_HTTP_CAINFO="$CA_PATH"
export AWS_CA_BUNDLE="$CA_PATH"

# Optional: install into system trust store if available.
if command -v update-ca-certificates >/dev/null 2>&1; then
  cp "$CA_PATH" /usr/local/share/ca-certificates/proxy.crt 2>/dev/null \
    && update-ca-certificates >/dev/null 2>&1 || true
fi

echo "Bootstrap complete. CA installed at $CA_PATH."
```

Caveat: `curl … | sh` runs the script in a *subshell*; exports don't propagate
to the parent. Recommended user-facing patterns:

- For interactive shells: `. <(curl -s http://proxy.local/bootstrap.sh)` (bash)
  or `eval "$(curl -s http://proxy.local/env.sh)"` (POSIX).
- For LLM agents: instruct the agent in `/llms.txt` to bootstrap as its first
  action and to keep working in the bootstrapped shell.
- For "I want it baked in": ship a Dockerfile snippet (3 lines) users can add
  to bake the CA into their image, sidestepping bootstrap entirely.

The `/setup` JSON endpoint exists for programmatic consumers (agents) that
want to introspect what to set rather than execute a script.

## Sandbox-side constraints

Things users should know about an agent container running behind the proxy:

- **One port unavailable on `0.0.0.0` and `127.0.0.1`:** `39999` (mitmproxy).
  Sandbox can still bind it on a specific non-loopback interface; in practice
  this never matters.
- **No `-p` on the agent container.** Docker rejects port publishing under
  `--network=container:`. Publish ports on the *sidecar* run command instead,
  pre-allocating a range like `-p 3000-3010:3000-3010` if the agent might run
  servers users want to reach from the host.
- **Sandbox-internal loopback is unaffected.** `localhost:*` traffic stays in
  the sandbox netns and never traverses iptables.
- **The sidecar must start before the agent container.** You cannot
  retroactively attach an already-running container to the proxy.
- **CA must be in trust before HTTPS to inject targets.** Tools spawned before
  bootstrap will see TLS errors. Three tiers of solution: (0) env vars only —
  works for most CLI tools; (1) entrypoint that runs bootstrap; (2) Dockerfile
  bake-in.

## Limitations

### Inherent (won't be fixed)

- **Cert pinning** on inject targets: TLS handshake fails. Documented
  workaround per case.
- **mTLS** to inject targets: cannot terminate without the client key.
- **Encrypted ClientHello (ECH):** SNI invisible; cannot decide intercept vs.
  passthrough. Rare today, growing.

### V1 limitations (may be addressed later)

- **HTTP/3 / QUIC:** dropped to force TCP fallback. Not intercepted.
- **IPv6:** dropped entirely.
- **Single sandbox per sidecar.** No multi-tenancy in v1.
- **No process attribution.** Cannot say which PID inside the sandbox made a
  request.

## Future extensions

These are *not* in v1 but inform the v1 design:

### Host plugin system

A Go binary on the host runs alongside the sidecar and hosts plugins. Plugins
are subprocesses speaking a JSON-RPC protocol over stdio (LSP / MCP-style).

Plugin types:

- **Credential providers** — resolve `value: "@op://…"` references against
  password managers, keychains, or other secret stores.
- **Approval UIs** — surface "agent wants credential X" prompts to the user.
- **Audit sinks** — record every injection / passthrough decision externally.
- **Policy decision points** — replace static config with dynamic decisions.

Sidecar↔host IPC: Unix socket (volume-mounted into the sidecar) or HTTP on a
known address. Methods (sketch):

- `credentials.get(host)` → `{header, value}`
- `approval.request(action, context)` → `{decision, until}`
- `audit.log(event)` → ack

The v1 addon should call its (currently in-process) credential lookup through
an interface that can be swapped for an IPC client later. Don't hard-code
direct config-file reads in the inject path.

### Other future work

- DNS-based egress allowlist (separate feature, requires DNS interception).
- Multi-tenant sidecar with per-sandbox config scoping (resolves which
  sandbox originated a request via source identification).
- `/events` endpoint for agent self-debugging — recent intercept decisions.
- Skills directory served by sidecar (if relevant to agent runtimes).
- Hot-reload of config without sidecar restart.
- Per-host TLS cert pinning enforcement (verify upstream cert hash before
  forwarding).

## V1 deliverables

- [ ] `Dockerfile` for the sidecar image.
- [ ] `entrypoint.sh` (iptables setup, mitmproxy launch).
- [ ] `addon.py` for mitmproxy (~200 lines: bootstrap endpoints, SNI gate,
      injection).
- [ ] `bootstrap.sh` template served by the addon.
- [ ] Python CLI `myproxy` (~200–400 lines).
- [ ] Example `config.yaml`.
- [ ] README with quickstart.
- [ ] One end-to-end smoke test: agent container hits `httpbin.org/headers`
      via inject host alias, verifies header arrived.

## Quickstart (target UX)

```bash
# Install
pipx install myproxy

# Configure
mkdir -p ~/.config/myproxy
cat > ~/.config/myproxy/config.yaml <<EOF
inject:
  api.github.com:
    header: Authorization
    value: "Bearer ghp_..."
EOF

# Start the sidecar (long-running)
myproxy start

# Run an agent container
myproxy run --image python:3.12 -- bash

# Inside the container:
$ eval "$(curl -s http://proxy.local/env.sh)"
$ curl -sI https://api.github.com/user | head -1
HTTP/2 200
```

## Open questions

These don't block v1 but should be settled before they accrue downstream
decisions:

1. **Should `bootstrap.sh` write env exports to `/etc/profile.d/proxy.sh`** so
   subshells inherit them? Tradeoff: less surprising for users who launch
   subshells vs. potentially writing into a read-only filesystem.
2. **Standard discovery URL?** `/.well-known/proxy-config` (RFC-style) vs.
   `proxy.local/setup` (custom). The former is more "right"; the latter is
   what we have.
3. **Config rotation.** Restart the sidecar vs. SIGHUP-style reload? Reload
   is friendlier but adds addon complexity.
4. **`/llms.txt` format.** Free-form text vs. AGENTS.md spec vs. a small
   structured schema the agent parses.
5. **Per-request injection logic** (path/method matching) in v1, or strictly
   per-host? v1 stays per-host; revisit if a real use case appears.
6. **Volume mount or HTTP-only for CA?** v1 uses HTTP-only (bootstrap
   endpoint). Consider also offering a volume mount for users who want it
   pre-positioned.

## Architecture decisions worth preserving

These are conclusions reached during design that future work should not
casually reverse:

- **Two-container shape is forced**, not chosen, by netfilter/netns physics
  and cross-platform requirements.
- **Sidecar holds the proxy core; host plugins handle host-touchy things.**
  Don't move proxy logic to the host without a strong reason. Don't put
  host-touchy logic in the sidecar.
- **Transparent intercept of all TCP, not port-based selection.** Goal is
  "every tool works"; selective capture leaks edge cases.
- **SNI-based decision, not IP-based.** CDN IPs are shared; IP-level rules
  over- or under-capture.
- **HTTP/3 forced to TCP fallback, not intercepted.** mitmproxy's QUIC support
  is experimental and clients fall back gracefully.
- **Bootstrap over plain HTTP from inside the netns is fine.** No eavesdropping
  threat in shared loopback / link-local; resolves the chicken-and-egg of
  trusting the trust source.
- **The sidecar image is opinionated and stable; the agent image is the user's.**
  Don't grow the sidecar to accommodate per-use-case features; push variability
  to config, host plugins, or different agent images.
