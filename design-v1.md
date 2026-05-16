# credproxy CLI — Persistent Instance Model (design v1)

## Status

A focused design for rewriting the host CLI (`bin/credproxy`). It supersedes
the ephemeral-session CLI sketched in `design-v0.md` and the current
implementation. The proxy container internals — mitmproxy addon, iptables,
the merged HTTP API, bootstrap routes — are **unchanged**; see `CLAUDE.md`
for those. This doc covers only the host-side CLI and the instance lifecycle
it manages.

Decided 2026-05-16. Like `design-v0.md`, this is a design sketch, not a
contract — divergence while implementing is expected. Once the rewrite
lands, fold the durable parts into `CLAUDE.md` (the living source of truth).

## Motivation

The current CLI treats a workspace as an ephemeral session: `credproxy
workspace` starts a proxy, runs one `--rm` container, and tears the proxy
down on exit. Clean as a single-command session, but it owns no state —
every run is a fresh container, and a long-running agent is tied to the
terminal that launched it.

The redesign treats a workspace as a **persistent, named instance** —
created once, started and stopped explicitly, reattached freely. The model
is borrowed from `limactl` (Lima): named instances, a `default` instance for
the no-argument path, explicit lifecycle verbs, home-centralized config.

This buys:

- Durable workspace state (tool installs, caches, agent scratch) across
  sessions.
- Long-running agents decoupled from any terminal — the workspace runs while
  the instance is *started*, independent of `shell` sessions attaching and
  detaching.
- Multiple named instances for different tasks (one runs at a time).

## Concepts

**Instance** — a named, persistent pair of containers:

- a **proxy container** (the credproxy proxy, unchanged), and
- a **workspace container** (the user's image), joined to the proxy's netns
  via `--network container:<proxy>`.

Both containers are long-lived: created once, then `docker start` / `stop`,
never `--rm`. An instance is identified by name; `default` is used when no
name is given and is auto-created on first use.

**One instance runs at a time.** Instances persist independently, but only
one instance's containers are in the running state at any moment — starting
an instance stops whichever is currently running. This is a deliberate
simplification: it keeps the proxy's host-published admin port fixed at
`127.0.0.1:39998` with no per-instance port allocation.

## Directory layout

All instance state is home-centralized under `~/.credproxy/` (override with
`$CREDPROXY_HOME`):

```
~/.credproxy/
  <name>/
    config.yaml     # the instance config (see below)
    auth.token      # per-instance proxy bearer token, mode 0644
```

The set of subdirectories *is* the instance registry — `credproxy list`
enumerates them and joins with `docker` state for status. Docker-managed
state (container writable layers, named volumes) lives in Docker, not here.

Container and volume names are derived from the instance name:

- proxy container: `credproxy-proxy-<name>`
- workspace container: `credproxy-ws-<name>`
- home volume: `credproxy-home-<name>`

## Instance config

One YAML file per instance, `~/.credproxy/<name>/config.yaml`. There is **no
multi-file precedence** — no Lima-style `_config/default.yaml` / `override.yaml`
merge layer. The file is the complete, effective config; `credproxy config
show` is therefore exact. A merge layer can be added later without breaking
existing instances. Three sections:

```yaml
# Workspace image. Changing this on an existing instance triggers a
# workspace-container recreate on the next `start` (see Lifecycle).
image: python:3.12-slim

# Where the persistent home volume mounts inside the workspace.
home: /root

# Host directories bind-mounted into the workspace. Absolute paths; ~ is
# expanded. Edited live on the host, shared with the container.
mounts:
  - source: ~/src/credproxy
    target: /workspace/credproxy
    readonly: false        # optional, default false

# Proxy intercept config — unchanged schema from design-v0.md / config.py.
# ${secret:NAME} refs are resolved from the host environment by the CLI
# before the config is pushed to the proxy.
hosts:
  api.github.com:
    headers:
      Authorization:
        placeholder: credproxy_test
        real: ${secret:GITHUB_PAT}
```

The CLI splits this file: `image` / `home` / `mounts` drive `docker run`;
`hosts` is resolved and POSTed to the proxy's `/admin/config`. Real secrets
are never stored in the file — only placeholders and `${secret:NAME}`
references resolved from host env at push time, so the file is safe to keep
and share.

## Persistence

Three layers, each with a different durability:

| Layer | Holds | Survives |
|---|---|---|
| Home volume (`credproxy-home-<name>`) at `home:` | dotfiles, shell history, tool caches, agent state | image change, recreate, stop/start |
| Bind mounts (`mounts:`) | project source, edited on the host | everything — it's the host filesystem |
| Workspace container writable layer | incidental `apt install`s, `/etc` edits | stop/start; **lost on recreate** |

On first `start`, Docker seeds the empty home volume from the image's
contents at `home:`, so a fresh instance still has the image's `/root`.

## Lifecycle

`credproxy start <name>`:

1. Stop the currently-running instance, if any (print a notice).
2. Create or start the proxy container; wait for `/health`.
3. Resolve `${secret:}` refs in `config.yaml` and POST `hosts` to
   `/admin/config`. Config is **always re-pushed** — the proxy's tmpfs
   config does not survive a `docker start`.
4. Create or start the workspace container, joined to the proxy netns, with
   the home volume and bind mounts attached.

`credproxy stop <name>` — stop the workspace container, then the proxy.
Containers and volumes remain.

`credproxy delete <name>` — stop if running; `docker rm` both containers;
`docker volume rm` the home volume; remove `~/.credproxy/<name>/`. Prompts
for confirmation.

**Recreate.** If `config.yaml`'s `image` / `mounts` / `home` no longer match
an existing container, `start` recreates the affected container(s). The
proxy and workspace are recreate-coupled — the workspace joins the proxy's
netns by container reference, so recreating the proxy forces recreating the
workspace. The home volume and bind mounts survive a recreate; the workspace
writable layer does not.

## Command surface

User-facing commands. `NAME` defaults to `default` everywhere.

| Command | Behavior |
|---|---|
| `credproxy create [NAME] [--image IMG]` | Scaffold `~/.credproxy/<NAME>/` (config.yaml from a template, auth.token). Does not start anything. |
| `credproxy start [NAME]` | Start the instance (sequence above). Auto-creates the instance if missing. |
| `credproxy stop [NAME]` | Stop the instance's containers. |
| `credproxy shell [NAME] [-- CMD]` | `exec` into the workspace (default `bash`). Auto-starts a stopped instance. The primary verb. |
| `credproxy list` | Instances and their status (running / stopped), with image. |
| `credproxy delete [NAME]` | Remove the instance, its containers, and its home volume. |
| `credproxy config [NAME] {show,edit,push}` | `show` prints config.yaml; `edit` opens `$EDITOR`; `push` re-resolves `${secret:}` and POSTs `hosts` to a running proxy. |
| `credproxy logs [NAME]` | Follow the proxy container logs. |

Harness commands — `build`, `test`, `reload` — operate on the credproxy
*source tree*, not on instances, and need the repo checkout. Recommendation:
namespace them as `credproxy dev {build,test,reload}` to keep the user-facing
surface clean. (See Open questions.)

## Example session

```
# First run — creates and enters the `default` instance.
$ credproxy shell
[credproxy] creating instance 'default'...
[credproxy] starting proxy + workspace...
root@workspace:/#

# A named instance for a specific task.
$ credproxy create gh --image node:22
$ credproxy config gh edit                  # add hosts: and mounts:
$ GITHUB_PAT=$(op read 'op://vault/gh/pat') credproxy start gh
$ credproxy shell gh

$ credproxy list
NAME      STATUS    IMAGE
default   stopped   python:3.12-slim
gh        running   node:22
```

## What this reverses

Relative to the current implementation:

- Ephemeral `--rm` workspace → persistent containers.
- Auto-start-proxy / teardown-on-exit (commit `6de7464`) → explicit
  `start` / `stop`.
- Singleton container name `credproxy` → per-instance names.
- Repo-bound paths (`.run/auth.token`, `proxy/config.yaml`) →
  `~/.credproxy/<name>/`.

None of CLAUDE.md's protected "don't casually reverse" decisions are
affected — the two-container shape, transparent capture, SNI-based intercept,
host-owned bearer, single HTTP listener, and the proxy-core / host-plugin
split are all unchanged.

## Open questions

- **Proxy CA persistence.** mitmproxy's CA lives in the proxy container's
  writable layer. It survives stop/start and crashes (same container) but
  not a *recreate*, where mitmproxy mints a fresh CA. This is milder than
  it first appears: a proxy recreate is coupled to a workspace recreate
  (the `credproxy.spec` label includes the proxy container id), and
  `bootstrap.sh` installs CA trust only into the workspace's writable
  layer — destroyed by that same recreate — so the workspace re-bootstraps
  anyway and never sits trusting a stale CA. It is a re-bootstrap cost,
  not silent breakage. Persisting the CA in a named volume
  (`credproxy-ca-<name>`) becomes genuinely necessary only if CA trust is
  later made durable across workspace recreates (e.g. bootstrap writes it
  into the home volume); the CLI-driven bootstrap idea under
  Auto-bootstrap sidesteps the question entirely.
- **Auto-bootstrap.** Whether `start` should run the bootstrap
  (`bootstrap.sh`: install CA + env vars) into the workspace
  automatically, instead of leaving the user to run `curl … | sh`.
  Bootstrap state lives in the writable layer, so it must re-run after a
  recreate. `bootstrap.sh` is idempotent and convergent — every step
  overwrites a fixed path or runs an idempotent tool — so running it on
  every `start` is safe. Design ideas to fold in when this is built:
  - **`auto_bootstrap` toggle.** A config key (default on) to opt out —
    for images that bake the CA in, or users who bootstrap by hand.
  - **`provision:` hook.** A Lima-style list of commands run via
    `docker exec` on workspace creation, *before* bootstrap — covers
    installing prerequisites such as `curl` (`apt-get` traffic is
    passthrough, so it works before the CA is trusted). A general
    provisioning hook is preferred over a bootstrap-specific
    "pre-bootstrap script".
  - **CLI-driven bootstrap.** The CLI already speaks HTTP to the proxy
    from the host, so it can fetch `/ca.crt` (+ `/env.sh`) itself and
    inject them via `docker cp` / `docker exec`. If `bootstrap.sh` skips
    its fetch when the cert is already present, one script serves both
    the manual and auto paths and the auto path needs no `curl` in the
    workspace image. Running this convergently on every `start` would
    also make the CA-persistence question above moot.
- **Harness namespacing.** Confirm `credproxy dev {build,test,reload}` vs.
  leaving those commands top-level.
- **Mount key names.** Confirm Docker-style `source` / `target` / `readonly`
  over Lima's `location` / `mountPoint` / `writable`; confirm `~` expansion
  and rejection of relative paths.
