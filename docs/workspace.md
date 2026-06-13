# Workspace

The **workspace** is whatever container the user runs to do their work
behind credproxy — an LLM agent, a CI runner, a dev shell, a batch job.
It joins the **proxy** container's network namespace via
`--network=container:credproxy-proxy-<name>`. The proxy owns the netns;
the workspace shares it.

The workspace image itself can be anything. No special build, no
`NET_ADMIN`, no installed CA, no environment variables. The constraints
below are about the workspace's *runtime configuration*, not its
contents.

## Docker run flags rejected by the daemon

Joining a foreign network namespace makes the workspace's own network
identity meaningless, so Docker rejects flags that try to set one:

| Flag | Daemon error |
|---|---|
| `--hostname` | `conflicting options: hostname and the network mode` |
| `--dns` | `conflicting options: dns and the network mode` |
| `--add-host` | `conflicting options: custom host-to-IP mapping and the network mode` |
| `--ip` (and `--ip6`) | `invalid config for network container:…` |
| `-p` / `--publish` / `-P` | `conflicting options: port publishing and the container type network mode` |

If you need any of these, set them on the **proxy**'s `docker run`
instead — the workspace will inherit them.

## Docker run flags accepted but ineffective

These don't error at start, but the proxy's bind-mounted files (see
below) make them no-ops or, worse, side-effects on the *proxy*:

- `--mac-address` — silently ignored; workspace uses the proxy's MAC.
- `--dns-search`, `--dns-option` — would need to write to
  `/etc/resolv.conf`, which is shared with the proxy.

Treat these as "don't bother."

## Files inherited from the proxy

`--network=container:` bind-mounts these from the proxy into the
workspace. Same inode, both directions:

- `/etc/hosts`
- `/etc/resolv.conf`
- `/etc/hostname`

Implications:

- Whatever the workspace image baked into these files at build time is
  **completely shadowed** at runtime.
- Edits the workspace makes (e.g., a startup script appending to
  `/etc/hosts`) are visible from the proxy and persist as long as the
  proxy lives.
- The workspace's effective hostname is the proxy's container hostname.

## Reserved in the shared netns

| Resource | Purpose |
|---|---|
| TCP `*:39998` | Merged HTTP API: bootstrap + admin (aiohttp) |
| TCP `*:39999` | mitmproxy transparent listener |
| IP `169.254.1.1` | Sentinel; resolves as `proxy.local` |

The workspace cannot bind 39998 or 39999 on `0.0.0.0` or `127.0.0.1`
(the proxy already holds them). It can in principle bind on a
non-loopback interface; in practice this never matters.

`/admin/*` routes on the HTTP API require a bearer token the workspace
does not have; they return 401 to the workspace. Bootstrap routes
(`/health`, `/ca.crt`, `/bootstrap.sh`, `/env.sh`, `/setup`,
`/llms.txt`) are open by design.

## Bootstrap

Run once (as root) to install the proxy CA and write env vars:

```sh
curl -sSL http://proxy.local/bootstrap.sh | sh
```

This fetches the CA, installs it system-wide (if `update-ca-certificates`
is available), and writes `/etc/profile.d/credproxy.sh` with the env
vars that tools like Python requests (certifi), Node, Cargo, and AWS SDKs
need to trust the CA.

After bootstrap, fetch the credential bindings to wire up your tools:

```sh
curl -s http://proxy.local/setup | jq .bindings
```

Each binding entry exposes: `name`, `placeholder` (the inert sentinel to
use as the credential value), `env` (suggested env var, may be null),
`header` (the HTTP header the proxy watches), and `hosts` (the hostnames
for which injection is active). The real credential is never exposed
here. Use `http://169.254.1.1` directly if `proxy.local` does not resolve.

The `/setup` response also includes a top-level `workspace` field — the
workspace's own name (or `null` if unknown) — handy for self-identification
such as a shell prompt: `WS=$(curl -s http://proxy.local/setup | jq -r .workspace)`.

## SELinux (Fedora / RHEL hosts)

On a host with SELinux enforcing, host bind mounts carry the host's label
(e.g. `user_home_t`), which a confined container cannot read. credproxy
handles this so mounts work out of the box, splitting by trust:

- **Proxy container** stays SELinux-confined (it is privileged and holds the
  real secrets). Its own bind mounts are relabeled: the bearer token with
  `:Z` (private) and, in dev, the bind-mounted source with `:z` (shared).
- **Workspace container** runs with `--security-opt label=disable` (as
  distrobox/toolbx do). This lets your bind-mounted project directories be
  read **without relabeling them** — credproxy never mutates the SELinux
  context of your own directories. The tradeoff is that the workspace
  container is not SELinux-confined; acceptable since it runs your own
  workload and the privileged proxy stays confined.

All of this is a no-op on hosts without SELinux (Docker/podman on
non-SELinux systems accept the flags and ignore them).

## Egress shape

What happens to packets the workspace originates:

- **All TCP** is redirected via iptables. Either to the bootstrap
  listener (for `169.254.1.1:80`) or to mitmproxy (everything else).
- **`localhost` / `127.0.0.0/8`** is exempted; workspace-internal
  services keep working unmodified.
- **IPv6** is dropped wholesale (`ip6tables -P OUTPUT DROP`).
- **UDP/443** is dropped to force HTTP/3 → HTTP/2 fallback.
- **DNS (UDP/53)** is left alone; the system resolver works normally.
- **ICMP** is left alone.

## Lifecycle

- **Proxy must start first.** You can't retroactively attach a running
  container to the proxy's netns.
- **Proxy going down kills the workspace's network.** The netns dies
  with the proxy; sockets in the workspace close.
- **Workspace can be restarted freely** while the proxy stays up. Each
  fresh workspace re-inherits the proxy's `/etc/hosts` etc.

## What the workspace does *not* need

- No `NET_ADMIN`, no `CAP_NET_BIND_SERVICE`, no privileged mode.
- No image modification, no preinstalled CA, no Dockerfile snippet.
- No environment variables (`HTTP_PROXY` etc.) — capture is transparent
  at the kernel level. Set them only if you specifically want CA trust;
  see `http://proxy.local/env.sh`.
