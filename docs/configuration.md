# Workspace configuration

A workspace is defined by a single TOML file. That file is the **source of
truth**: imperative commands (`workspace create`, `binding add`, …) are sugar
that edit it, and every change they make is something you could have typed into
the file yourself. There is no hidden state and no separate "saved" copy — what
the file says is what the workspace is.

This doc covers both paths: the **file format** and the **CLI** that edits and
applies it. For the netns/bootstrap side of a running workspace see
[`workspace.md`](workspace.md); for writing credential backends see
[`providers.md`](providers.md).

## Where config lives

| Path | Holds |
|---|---|
| `$XDG_CONFIG_HOME/credproxy/workspaces/<name>.toml` | the workspace config (this doc). Default `~/.config/credproxy/workspaces/`. The file existing **is** the workspace existing. |
| `$XDG_CONFIG_HOME/credproxy/injectors/<name>.toml` | your injector definitions (shadow the bundled ones) |
| `$XDG_CONFIG_HOME/credproxy/providers/<name>` | your provider executables (shadow the bundled ones) |
| `$XDG_STATE_HOME/credproxy/workspaces/<name>/` | runtime state — `auth.token`, the last-applied spec/bindings, session pidfiles. Not hand-edited. Default `~/.local/state/credproxy/`. |
| `$XDG_STATE_HOME/credproxy/default-workspace` | the current default-workspace pointer (loose surface) |

The config dir is editable; the state dir is owned by the tool. Point the two
XDG variables elsewhere to keep separate sets of workspaces (this is also how
the tests isolate themselves).

## The file format

A complete example, with every key shown:

```toml
# Workspace container image.
image = "python:3.12-slim"

# Where the persistent home volume mounts inside the workspace.
home = "/root"

# User that `enter` runs as (docker exec -u). Must exist in the image or be
# created by `setup` (which runs as root). Exec-only — no recreate.
user = "dev"

# Escape hatch: extra flags spliced into `docker exec` for `enter`.
# credproxy keeps control of -i/-t/-d. Exec-only.
exec_flags = ["--workdir", "/srv"]

# Host paths bind-mounted in. Each entry is "SRC:DST" or "SRC:DST:ro".
mounts = [
  "~/code:/code",
  "~/.gitconfig:/root/.gitconfig:ro",
]

# Environment variables set in the workspace container.
env = { GH_DEBUG = "1", TZ = "UTC" }

# Commands run once, after the container is (re)created.
setup = [
  "npm ci",
]

# Stop the workspace when the last `enter` session exits. Off by default.
auto_stop = true

# Credential bindings — zero or more. See "Bindings" below.
[[binding]]
name        = "github-api"        # auto-generated if omitted
injector    = "bearer"
provider    = "env"
secret      = "GITHUB_TOKEN"      # single-slot: a bare ref
hosts       = ["api.github.com"]
placeholder = "ghp_…"             # auto-generated if omitted
env         = "GITHUB_TOKEN"      # defaults to the injector's hint

# A multi-slot secret uses an inline table (slot -> provider ref) instead of a
# bare string; the scheme declares which slots it needs. E.g. a sigv4 binding
# (sign family — no placeholder; the proxy re-signs each request):
[[binding]]
injector = "sigv4"
provider = "env"
secret   = { access_key_id = "AWS_ACCESS_KEY_ID", secret_access_key = "AWS_SECRET_ACCESS_KEY" }
hosts    = ["sts.amazonaws.com"]
```

### Container settings

| Key | Type | Default | Notes |
|---|---|---|---|
| `image` | string | `python:3.12-slim` | The workspace container image — your own image; never modified or privileged. |
| `home` | string | `/root` | Mount point of the persistent home volume inside the container. Must be absolute. The volume survives stop/start and recreate; it is removed only by `delete`. |
| `mounts` | list of strings | `[]` | Each entry is `"SRC:DST"` or `"SRC:DST:ro"`. `~` is expanded on `SRC`; `SRC` must be an existing absolute path, `DST` must be absolute. `:ro` makes the mount read-only. |
| `env` | table (string → string) | `{}` | Passed to the container as `-e KEY=VALUE`. Both keys and values must be strings. |
| `setup` | list of strings | `[]` | Shell commands run **once**, right after the container is (re)created, via `sh -lc`. A failing command stops `start` and leaves the container in place for debugging. Re-run only happens when the container is recreated (see drift below), not on every `start`. |
| `run_flags` | list of strings | `[]` | Escape hatch: extra flags spliced into the workspace `docker run`. credproxy's structural flags (`--name`, labels, `--network`, the home volume) are applied **after** these and win on conflict, so `run_flags` can't detach the netns or rename the container; additive flags (`--userns`, an extra `--mount`/`-v`, `--security-opt`) take effect. The main use is runtime-specific uid mapping (see *Non-root user & mount ownership* below). |
| `auto_stop` | bool | `false` | When `true`, the workspace stops once the last `enter` session exits. Read fresh at session end, so toggling it mid-session takes effect immediately. A stopped workspace is resumed automatically by the next `enter`. |

Changing `image`, `home`, `mounts`, `env`, `setup`, or `run_flags` is
**container-spec drift**: it requires recreating the workspace container, which
happens on the next `start` (the home volume is preserved). Editing bindings
does **not** require a recreate — see below.

### Exec settings

These shape how `enter` runs commands in the container; they are **exec-only**
(not part of the container spec), so changing them takes effect on the next
`enter` with **no recreate**.

| Key | Type | Default | Notes |
|---|---|---|---|
| `user` | string | image default (root) | Runs `enter` (and `enter -- cmd`) as this user via `docker exec -u`. The user must exist in the image — built in, or created by `setup`, which always runs as **root** (so it can `useradd`, add sudoers, and `chown` the home volume to the user). `enter --user NAME` overrides it for one session (e.g. `enter --user root` for a debug shell). |
| `exec_flags` | list of strings | `[]` | Escape hatch: extra flags spliced into the `docker exec` for `enter` (e.g. `["--workdir", "/srv"]`, `["--env", "FOO=bar"]`). credproxy keeps ownership of the session-control flags (`-i`/`-t`/`-d`), so these can't detach the session or break auto-stop. |

`setup` runs as root regardless of `user`, so it is the place to provision a
non-root user (create it, grant sudo, chown its home).

### Non-root user & mount ownership

Running the workspace as a non-root `user` (above) and bind-mounting host
directories into it runs into a runtime-specific ownership problem, and there is
no single portable flag for it — rootful and rootless runtimes have opposite uid
models. credproxy never changes host-file ownership to paper over this; instead
you pick the right lever per runtime. In every case the host bytes and ownership
are left untouched.

Every workspace gets `CREDPROXY_HOST_UID` / `CREDPROXY_HOST_GID` in its
environment — the uid/gid the CLI runs as, i.e. the owner of your bind-mounted
project dirs. That single value is the canonical "workspace uid" on both
runtimes, so the recipes reference it instead of a hardcoded number:

- **Rootful Docker / Docker Desktop (macOS):** container uid `N` == host uid `N`.
  Create the non-root user with that uid in `setup`
  (`useradd -u "$CREDPROXY_HOST_UID" -g "$CREDPROXY_HOST_GID" dev`) and the bind
  mounts are writable as that user. (On Docker Desktop the file share is usually
  permissive already, so this often just works.) No `run_flags` needed.
- **Rootless Podman (Linux):** the user namespace maps your host uid to container
  **root**, so a non-root user can't write the mounts by default. Map your host
  uid onto the container user with
  `run_flags = ["--userns=keep-id:uid=1000,gid=1000"]`, then create `dev` with
  the matching uid in `setup`. Both the bind mounts and the home volume then line
  up. A per-mount `-v SRC:DST:idmap` is the finer-grained alternative.
  (`run_flags` can't read the env var — TOML is static — so use the same literal
  uid in the flag and the `useradd`.)

`run_flags` is part of the container spec, so changing it recreates the
workspace on the next `start`.

### Bindings

A `[[binding]]` block ties an **injector** (how a credential is shaped into a
request — which typed scheme the proxy runs) to a **provider** (where its value
comes from), scoped to a set of hosts. The real secret never enters the
workspace: the workspace holds only the inert `placeholder`, and the proxy swaps
it for the real value on requests to the scoped hosts.

| Field | Required | Notes |
|---|---|---|
| `injector` | yes | Name of an injector definition (`$XDG_CONFIG_HOME/credproxy/injectors/<name>.toml`, falling back to bundled). Selects the scheme, its params, and the placeholder shape. Bundled: `bearer`, `basic`, `body`. |
| `provider` | yes | Name of a provider executable (`$XDG_CONFIG_HOME/credproxy/providers/<name>`, falling back to bundled). Bundled: `env`. |
| `secret` | yes | Either a bare ref string (single-slot), or an inline table mapping the scheme's slot names to refs (multi-slot). A ref is opaque to credproxy and meaningful only to the provider — an env-var name, a vault path, an item id. |
| `hosts` | yes | Non-empty list of hostnames the credential may be injected on. This is the security scope: a request to any other host never sees the real value. |
| `name` | no | Handle used to address the binding (`binding remove`, `binding test NAME`). Auto-generated as `<injector>-<provider>`, with a `-2`, `-3`, … suffix on collision. |
| `placeholder` | no | The inert sentinel the workspace sends (substitute schemes). Auto-generated once from the injector's placeholder pattern (format-valid for the service), then written back to the file so it never drifts. Override only if you need a specific value. |
| `env` | no | Suggested env var name surfaced to the workspace via `/setup`. Defaults to the injector's `env` hint. |

**Materialization.** When the tool loads a binding that omits `name` or
`placeholder`, it generates them and writes them back into the TOML with a
surgical edit that preserves your comments and ordering. After that the values
are static — the file stays the single source of truth, with nothing held only
in memory.

**Validation.** Binding names must be unique within the workspace, and no two
bindings may write the same wire location on the same host (e.g. both into the
`Authorization` header on `api.github.com`). The binding's secret slots must
match the scheme's declared slots. The referenced injector and provider must
resolve. Violations are reported as a config error naming the file and the
offending field.

**Presets.** Some credentials need several coordinated bindings — a GitHub PAT
is `bearer` on `api.github.com` but HTTP `basic` on `github.com`/`ghcr.io`.
`binding add --preset github --provider env --secret GITHUB_TOKEN` generates the
whole set, all sharing one bare-token placeholder, so there is no hand-computed
base64 and no fragile coupling. The result is ordinary `[[binding]]` blocks you
can edit or remove individually.

Injector definitions are a separate declarative file type (scheme, params,
placeholder pattern, env hint) — see [`injectors.md`](injectors.md). Providers
are host-side executables — see [`providers.md`](providers.md).

## The CLI path

Every imperative command maps to an edit of, or an action driven by, the same
file. You can always skip the command and edit the TOML directly.

| Command | Effect on the config |
|---|---|
| `credproxy workspace create NAME [--image IMG]` | Scaffold `<name>.toml` (and the state dir + `auth.token`). Does not start anything. |
| `credproxy workspace NAME binding add --injector I --provider P --secret REF --host H [--host H…] [--name N] [--placeholder PH] [--env E]` | Append a `[[binding]]` block, materializing `name`/`placeholder` immediately. Validates the whole set before writing, so a rejected binding never lands in the file. Repeat `--secret SLOT=REF` for a multi-slot secret; a single `--secret SLOT=REF` works too when `SLOT` is the scheme's slot name (e.g. `jwt-bearer`'s `private_key`). |
| `credproxy workspace NAME binding add --preset PRESET --provider P --secret REF` | Generate a coordinated binding set from a preset (e.g. `github`), all sharing one placeholder. The preset manages name/placeholder/env/host. |
| `credproxy workspace NAME binding remove BINDING_NAME` | Remove that binding's block (surgical text edit). Reversible in principle, but loses tuning — gated by confirmation when targeting the default workspace on the loose surface. |
| `credproxy workspace NAME binding list` | Read and print the bindings (materializing any missing `name`/`placeholder` first). Shows name, injector, provider, secret-id, hosts, env, and placeholder. |
| `credproxy workspace NAME binding test [BINDING_NAME]` | Dry-run: fetch each binding's secret through its provider and report success and **value length only** (never the value). Exit 1 if any fail. |
| `credproxy workspace binding test --provider P --secret REF [--injector I]` | Ad-hoc variant: test a provider/injector combination **before** binding it. No workspace is required. |
| `credproxy workspace NAME edit` | Open `<name>.toml` in `$VISUAL`/`$EDITOR` (default `vi`), then validate it: warns if the edit left it invalid (without reverting), otherwise hints `apply`/`start`. Pure sugar over opening the file yourself. |
| `credproxy workspace NAME inspect` | Read-only: print the parsed config, container state, resolved host port, binding summary, and **itemized drift** between the file and what is currently applied. |
| `credproxy workspace NAME apply` | Reconcile a running workspace to the edited file (see below). |

There is intentionally **no** `config show` command — the file is a first-class
path and `inspect` is the read-and-diff view. `edit` is the one editor
convenience: it just opens that same file in `$EDITOR` and validates the result,
adding no state of its own.

### Applying changes

A file edit is not picked up automatically. How a change takes effect depends on
what you changed:

- **Bindings** are live-applicable. On a running workspace, `apply` re-resolves
  each binding's secret through its provider and pushes the new wire config to
  the proxy — no restart, no dropped connections.
- **Container settings** (`image`, `home`, `mounts`, `env`, `setup`) cannot be
  changed on a live container. `apply` reports them as **deferred** with a hint;
  `start` performs the recreate (preserving the home volume) and re-runs
  `setup`.

`apply` reports what it applied versus deferred; `inspect` shows the same drift
ahead of time, item by item. `start` always re-pushes bindings once the proxy is
healthy, because the proxy's config lives on tmpfs and does not survive a
`stop`/`start`.

```sh
# edit the file, then:
credproxy workspace myproj inspect   # what differs?
credproxy workspace myproj apply     # push binding changes live
credproxy workspace myproj start     # recreate for image/mounts/env/setup changes
```
