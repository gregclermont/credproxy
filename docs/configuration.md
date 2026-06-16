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
| `$XDG_CONFIG_HOME/credproxy/injectors/<name>.toml` | your injector definitions (shadow the builtin ones) |
| `$XDG_CONFIG_HOME/credproxy/providers/<name>` | your provider executables (shadow the builtin ones) |
| `$XDG_STATE_HOME/credproxy/workspaces/<name>/` | runtime state — `auth.token`, the last-applied spec/bindings, session pidfiles. Not hand-edited. Default `~/.local/state/credproxy/`. |
| `$XDG_STATE_HOME/credproxy/default-workspace` | the current default-workspace pointer (loose surface) |

The config dir is editable; the state dir is owned by the tool. Point the two
XDG variables elsewhere to keep separate sets of workspaces (this is also how
the tests isolate themselves).

## The file format

A complete example, with every key shown:

```toml
# Workspace container image. The default ships a non-root sudo user (vscode).
image = "mcr.microsoft.com/devcontainers/base:ubuntu"

# Where the persistent home volume mounts inside the workspace. Point it at the
# user's home so the volume is their home (the default image pre-creates
# /home/vscode owned by vscode, so it seeds correctly — no chown needed).
home = "/home/vscode"

# User that `enter` runs as (docker exec -u). Must exist in the image (the
# default image ships `vscode`, uid 1000, passwordless sudo) or be created by
# `setup` (which runs as root). Exec-only — no recreate.
user = "vscode"

# Directory `enter` starts in (the workspaceFolder analog). Defaults to `home`.
workdir = "/code"

# Make `user` own the bind mounts without changing host ownership; credproxy
# picks the per-runtime lever. No-op unless `user` is set. Recreates on change.
map_host_user = true

# Escape hatch: extra flags spliced into `docker exec` for `enter`.
# credproxy keeps control of -i/-t/-d. Exec-only.
exec_flags = ["--workdir", "/srv"]

# Host paths bind-mounted in. Each entry is "SRC:DST" or "SRC:DST:ro".
mounts = [
  "~/code:/code",
  "~/.gitconfig:/home/vscode/.gitconfig:ro",
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
| `image` | string | **required** | The workspace container image — your own image; never modified or privileged. `credproxy create` scaffolds this to a devcontainers base that ships a non-root sudo user (`vscode`, uid 1000) plus curl + ca-certificates (so the bootstrap and a non-root shell work with no setup), along with the matching `user`/`home`/`map_host_user`. To run a different image, edit `image` here (and `user`/`home` to match — the scaffold comments explain). There is no built-in default: `image` is mandatory, and omitting it is an error. |
| `home` | string | `/root` | Mount point of the persistent home volume inside the container. Must be absolute. The volume survives stop/start and recreate; it is removed only by `delete`. |
| `mounts` | list of strings | `[]` | Each entry is `"SRC:DST"` or `"SRC:DST:ro"`. `~` is expanded on `SRC`; `SRC` must be an existing absolute path, `DST` must be absolute. `:ro` makes the mount read-only. |
| `env` | table (string → string) | `{}` | Passed to the container as `-e KEY=VALUE`. Both keys and values must be strings. |
| `setup` | list of strings | `[]` | Shell commands run **once**, right after the container is (re)created, via `sh -lc`. A failing command stops `start` and leaves the container in place for debugging. Re-run only happens when the container is recreated (see drift below), not on every `start`. |
| `run_flags` | list of strings | `[]` | Escape hatch: extra flags spliced into the workspace `docker run`. credproxy's structural flags (`--name`, labels, `--network`, the home volume) are applied **after** these and win on conflict, so `run_flags` can't detach the netns or rename the container; additive flags (`--userns`, an extra `--mount`/`-v`, `--security-opt`) take effect. The main use is runtime-specific uid mapping (see *Non-root user & mount ownership* below). |
| `map_host_user` | bool | `false` | Make the non-root `user` own your bind mounts without changing host ownership. credproxy picks the runtime-appropriate lever automatically (`--userns=keep-id` on rootless podman; a no-op on Docker, where the matching uid does it). **Requires `user`** (error otherwise). The managed alternative to a hand-written `--userns` in `run_flags` — and if you set both, the `run_flags` one wins (escape hatch overrides the knob). See *Non-root user & mount ownership* below. |
| `user_uid` | int | host uid | The in-container uid of `user` — the uid `map_host_user`'s keep-id maps your host uid **onto** (rootless podman). Host uid and this need not be equal; keep-id maps across them. Defaults to your host uid (correct for a `setup`-provisioned user made as `$CREDPROXY_HOST_UID`); set it to a baked user's uid (the default image's `vscode` is `1000`, which the scaffold fills in). **Requires `user`** (error otherwise). Only consumed with `map_host_user` on rootless podman. |
| `auto_stop` | bool | `false` | When `true`, the workspace stops once the last `enter` session exits. Read fresh at session end, so toggling it mid-session takes effect immediately. A stopped workspace is resumed automatically by the next `enter`. |

Changing `image`, `home`, `mounts`, `env`, `setup`, `run_flags`, or
`map_host_user` is **container-spec drift**: it requires recreating the
workspace container, which happens on the next `start` (the home volume is
preserved). Editing bindings does **not** require a recreate — see below.

### Exec settings

These shape how `enter` runs commands in the container; they are **exec-only**
(not part of the container spec), so changing them takes effect on the next
`enter` with **no recreate**.

| Key | Type | Default | Notes |
|---|---|---|---|
| `user` | string | image default (root) | Runs `enter` (and `enter -- cmd`) as this user via `docker exec -u`. The user must exist in the image — built in, or created by `setup`, which always runs as **root** (so it can `useradd`, add sudoers, and `chown` the home volume to the user). `enter --user NAME` overrides it for one session (e.g. `enter --user root` for a debug shell). |
| `shell` | list of strings | `["bash", "-l"]` | Command `enter` runs when you don't pass `-- CMD` (argv list). Defaults to a **login shell** — semantically entering the workspace is "logging in" (the ssh model), so the interactive entry sources the full login environment; `enter -- CMD` stays a bare, non-login command (the ssh `host cmd` model). Set e.g. `["zsh"]` to change the entry shell, or `["bash"]` for a non-login one. |
| `workdir` | string | `home` | Directory `enter` starts in (`docker exec --workdir`) — the `workspaceFolder` analog. Defaults to `home`, so you land in your home dir rather than the image's `WORKDIR` (`/` on the devcontainers base); point it at a bind-mounted project to land there. Must be absolute. A `--workdir` in `exec_flags` still overrides it (docker last-wins). |
| `enter_prelude` | string | source the CA-env file | A shell snippet run before the enter command, via `sh -c '<prelude>; exec "$@"'`. The default sources the proxy's bootstrap-written env file (`/etc/profile.d/credproxy.sh`) so the HTTPS-CA env vars reach an interactive shell, `enter -- cmd`, **and** subprocesses — `docker exec` is a bare `execve`, so without this the env only loads in a login shell. `exec "$@"` keeps it transparent (no extra PID; signals/TTY/exit code/argv pass through). Set to `""` to skip wrapping (direct `execve`, no `/bin/sh` dependency). |
| `exec_flags` | list of strings | `[]` | Escape hatch: extra flags spliced into the `docker exec` for `enter` (e.g. `["--workdir", "/srv"]`, `["--env", "FOO=bar"]`). credproxy keeps ownership of the session-control flags (`-i`/`-t`/`-d`), so these can't detach the session or break auto-stop. |

`setup` runs as root regardless of `user`, so it is the place to provision a
non-root user (create it, grant sudo, chown its home).

### Injected environment

Beyond your `env` table, every workspace gets a few read-only breadcrumbs in its
environment — handy for `setup` scripts, shell rc, and a tenant that wants to
self-configure. They are stable per workspace/host, so (unlike `env`) they are
**not** part of the container spec hash and never cause a recreate; an existing
container picks up a newly added one on its next recreate. Your `env` is applied
last, so a key you set there shadows the breadcrumb of the same name.

| Variable | Value |
|---|---|
| `CREDPROXY_SETUP` | `http://proxy.local/llms.txt` — where a tenant (e.g. an agent) reads its own setup guidance. `proxy.local` resolves via `/etc/hosts`; `/setup` serves the machine-readable least-disclosure binding shape. |
| `CREDPROXY_WORKSPACE` | The workspace's own name — so a setup script or prompt label can read it instead of templating the literal name (also available via `/setup`). |
| `CREDPROXY_HOST_UID` / `CREDPROXY_HOST_GID` | The uid/gid the CLI runs as, i.e. the owner of your bind-mounted project dirs. The value to match a `setup`-created user to (`useradd -u $CREDPROXY_HOST_UID`) — see *Non-root user & mount ownership* below. |

### Non-root user & mount ownership

Running the workspace as a non-root `user` (above) and bind-mounting host
directories into it runs into a runtime-specific ownership problem, and there is
no single portable flag for it — rootful and rootless runtimes have opposite uid
models. credproxy never changes host-file ownership to paper over this; instead
you pick the right lever per runtime. In every case the host bytes and ownership
are left untouched.

The lever here is `CREDPROXY_HOST_UID` / `CREDPROXY_HOST_GID` (see *Injected
environment* above) — the uid/gid the CLI runs as, i.e. the owner of your
bind-mounted project dirs. It's the value to match a `setup`-created user to
(`useradd -u $CREDPROXY_HOST_UID`).

#### The mental model

The workspace `user` runs as some uid **inside** the container — call it
`user_uid`. For it to read/write your bind mounts (owned on the host by you,
`CREDPROXY_HOST_UID`), your host identity has to map to `user_uid` inside. **How**
that mapping works — and **whether the host uid and `user_uid` may differ** —
depends on the runtime:

- **Rootless podman:** `map_host_user` adds `--userns=keep-id:uid=<user_uid>`,
  which maps **your host uid onto `user_uid`**. The two **need not be equal** —
  keep-id maps *across* them — so a baked `vscode` (uid 1000) works even when your
  host uid is 501. credproxy just needs to know `user_uid` (it defaults to your
  host uid; the scaffold sets `1000` for the default image).
- **Rootful Docker (Linux):** container uid **==** host uid — no remapping, no
  keep-id. So here `user_uid` **must equal** your host uid for the mounts to line
  up, and `map_host_user` is a no-op. You match them by creating the user as
  `$CREDPROXY_HOST_UID`; the baked `vscode` (1000) lines up **only** at host uid
  1000.
- **Docker Desktop (macOS):** the file share is permissive — uid doesn't matter,
  it just works.
- **Rootless Docker:** no `keep-id` equivalent — **not covered**; you'd need
  idmapped bind mounts.

**Nested mount parents.** A bind target nested below `home`
(`~/src/proj:/home/vscode/src/proj`) makes the runtime fabricate the intermediate
`/home/vscode/src` as container-root — so even though the mount itself ends up
user-owned, that parent isn't, and the user can't create siblings there (a second
clone under `~/src`). Under `map_host_user` credproxy re-owns those fabricated
parents to the user's uid on each (re)create — a non-recursive `chown` of only the
dirs between `home` and the target (never the mount point, never host files),
runtime-agnostic (the parent is root on podman *and* rootful Docker). On the
manual `run_flags` path it's yours to handle (the namespace is yours).

So `user_uid` is the one knob, and it bites in exactly one place: it's the
in-container uid that keep-id targets on rootless podman. Set it wrong and the
mount shows up owned by the wrong uid inside (keep-id maps host-you onto *exactly*
that uid). `map_host_user` and `user_uid` are part of the container spec, so
changing either recreates the workspace on the next `start`. The host files are
never chowned in any case.

#### Supplying `user_uid`

**A baked user with a known uid** (the default image's `vscode` is `1000`) — tell
credproxy the uid; host uid and the user's uid then differ freely (podman):
```toml
user = "vscode"
user_uid = 1000          # the scaffold fills this in for the default image
map_host_user = true
mounts = ["~/code:/code"]
```

**A user you create in `setup`** — give it your host uid, and omit `user_uid`
(it defaults to the host uid, which then matches on podman *and* rootful Docker):
```toml
user = "dev"
map_host_user = true
mounts = ["~/code:/code"]
setup = ["useradd -u $CREDPROXY_HOST_UID -m dev || true"]
```

#### The manual path: `run_flags`

If you'd rather own the user namespace yourself (or need a non-default mapping),
skip `map_host_user` and write the flag directly:

- **Rootful Docker / Docker Desktop (macOS):** uids are 1:1, so just
  `useradd -u "$CREDPROXY_HOST_UID" dev` in `setup`; no `run_flags` needed.
- **Rootless Podman (Linux):** `run_flags = ["--userns=keep-id:uid=1000,gid=1000"]`
  plus a matching `useradd`. (`run_flags` is static TOML and can't read the env
  var, so use the same literal uid in both.) A per-mount `-v SRC:DST:idmap` is the
  finer-grained alternative.

To just change which in-container uid the mapping targets, prefer `user_uid` (above)
— `run_flags` is for a genuinely custom userns (an explicit `--uidmap`, multiple
ranges, etc.). If you set **both** `map_host_user` and a `--userns` in `run_flags`,
the `run_flags` one wins — `run_flags` is the escape hatch and overrides the
convenience knob (it's spliced after credproxy's `keep-id`, but still before the
structural flags, so it can't touch the netns).

### Bindings

A `[[binding]]` block ties an **injector** (how a credential is shaped into a
request — which typed scheme the proxy runs) to a **provider** (where its value
comes from), scoped to a set of hosts. The real secret never enters the
workspace: the workspace holds only the inert `placeholder`, and the proxy swaps
it for the real value on requests to the scoped hosts.

| Field | Required | Notes |
|---|---|---|
| `injector` | yes | Name of an injector definition (`$XDG_CONFIG_HOME/credproxy/injectors/<name>.toml`, falling back to builtin). Selects the scheme, its params, and the placeholder shape. Builtin: `bearer`, `basic`, `body`. |
| `provider` | yes | Name of a provider executable (`$XDG_CONFIG_HOME/credproxy/providers/<name>`, falling back to builtin). Builtin: `env`. |
| `secret` | yes | Either a bare ref string (single-slot), or an inline table mapping the scheme's slot names to refs (multi-slot). A ref is opaque to credproxy and meaningful only to the provider — an env-var name, a vault path, an item id. |
| `hosts` | yes | Non-empty list of hostnames the credential may be injected on. This is the security scope: a request to any other host never sees the real value. Each entry is a literal hostname (exact match) **or** a glob pattern containing `*` — see *Host patterns* below. |
| `name` | no | Handle used to address the binding (`binding remove`, `binding test NAME`). Auto-generated as `<injector>-<provider>`, with a `-2`, `-3`, … suffix on collision. |
| `placeholder` | no | The inert sentinel the workspace sends (substitute schemes). Auto-generated once from the injector's placeholder pattern (format-valid for the service), then written back to the file so it never drifts. Override only if you need a specific value. |
| `env` | no | Suggested env var name surfaced to the workspace via `/setup`. Defaults to the injector's `env` hint. |

**Materialization.** When the tool loads a binding that omits `name` or
`placeholder`, it generates them and writes them back into the TOML with a
surgical edit that preserves your comments and ordering. After that the values
are static — the file stays the single source of truth, with nothing held only
in memory.

**Host patterns.** A `hosts` entry without `*` is matched exactly (the common
case, and the fast path). An entry containing `*` is a **glob**, where `*` spans
any characters including dots — so one binding can cover a family of endpoints:

```toml
hosts = ["*.amazonaws.com"]        # any AWS service, any region
hosts = ["s3.*.amazonaws.com"]     # S3 only, any region
hosts = ["github.com", "api.github.com"]   # literals (exact), unchanged
```

This is what `sigv4` wants: it reads region and service from each request, so a
single `*.amazonaws.com` binding re-signs every regional endpoint with one real
key. Patterns are validated strictly, because this scope decides where a real
credential is injected: the two rightmost labels must be literal, so
`*.example.com` and `s3.*.amazonaws.com` are allowed but `*`, `*.com`, and
`*.*` are rejected (an over-broad pattern can't inject a credential into an
attacker-chosen host). A literal host always takes priority over a pattern that
also matches it; if two *different* patterns overlap, both apply in file order
(the later one wins a shared header).

**Validation.** Binding names must be unique within the workspace, and no two
bindings may write the same wire location on the same host (e.g. both into the
`Authorization` header on `api.github.com`). For glob hosts this collision check
is by pattern string — two identical patterns collide, but two *different*
overlapping patterns are resolved at request time (file order) rather than
rejected. The binding's secret slots must match the scheme's declared slots. The
referenced injector and provider must resolve. Violations are reported as a
config error naming the file and the offending field.

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
| `credproxy workspace create NAME` | Scaffold `<name>.toml` (and the state dir + `auth.token`) from the workspace template. Does not start anything. To use a non-default image, edit the scaffolded `image`. |
| `credproxy workspace NAME binding add --injector I --provider P --secret REF --host H [--host H…] [--name N] [--placeholder PH] [--env E]` | Append a `[[binding]]` block, materializing `name`/`placeholder` immediately. Validates the whole set before writing, so a rejected binding never lands in the file. Repeat `--secret SLOT=REF` for a multi-slot secret; a single `--secret SLOT=REF` works too when `SLOT` is the scheme's slot name (e.g. `jwt-bearer`'s `private_key`). |
| `credproxy workspace NAME binding add --preset PRESET --provider P --secret REF` | Generate a coordinated binding set from a preset (e.g. `github`), all sharing one placeholder. The preset manages name/placeholder/env/host. |
| `credproxy workspace NAME binding remove BINDING_NAME` | Remove that binding's block (surgical text edit). Reversible in principle, but loses tuning — gated by confirmation when targeting the default workspace on the loose surface. |
| `credproxy workspace NAME binding list` | Read and print the bindings (materializing any missing `name`/`placeholder` first). Shows name, injector, provider, secret-id, hosts, env, and placeholder. |
| `credproxy workspace NAME binding test [BINDING_NAME]` | Dry-run: fetch each binding's secret through its provider and report success and **value length only** (never the value). Exit 1 if any fail. |
| `credproxy workspace binding test --provider P --secret REF [--injector I]` | Ad-hoc variant: test a provider/injector combination **before** binding it. No workspace is required. |
| `credproxy workspace NAME edit` | Open `<name>.toml` in `$VISUAL`/`$EDITOR` (default `vi`), then validate it: warns if the edit left it invalid (without reverting), otherwise hints `apply`/`start`. Pure sugar over opening the file yourself. |
| `credproxy workspace NAME config [--declared]` | Read-only: dump the container-side config. Default `effective` — every field with its in-effect value, all defaults filled (including the enter-time `workdir`→home and `enter_prelude`→shim defaults `inspect` leaves null), so you can see what actually applies even when it's not in the file. `--declared` shows only what's literally in the TOML. `--json` on both. |
| `credproxy workspace NAME inspect` | Read-only: print the parsed config, container state, resolved host port, binding summary, and **itemized drift** between the file and what is currently applied. |
| `credproxy workspace NAME apply` | Reconcile a running workspace to the edited file (see below). |

These read-only views are projections of the file, with no state of their own:
`config` shows the config values (effective or declared), `inspect` adds
container state and **drift**, and `edit` just opens the same `<name>.toml` in
`$EDITOR` and validates the result. The TOML file remains the single source of
truth.

### Applying changes

A file edit is not picked up automatically. How a change takes effect depends on
what you changed:

- **Bindings** are live-applicable. On a running workspace, `apply` re-resolves
  each binding's secret through its provider and pushes the new wire config to
  the proxy — no restart, no dropped connections.
- **Container settings** (`image`, `home`, `mounts`, `env`, `setup`) cannot be
  changed on a live container. `apply` reports them as **deferred** with a hint;
  `start` performs the recreate (preserving the home volume) and re-runs
  `setup`. To force a rebuild on demand — even with no drift, e.g. to re-run
  `setup` or get a clean container — use `recreate` (workspace container only;
  `recreate --proxy` also rebuilds the proxy and regenerates its CA). Like
  `start`, it preserves the home volume, config, token, and state. To *also*
  start from a clean home, `recreate --reset-home` wipes the home volume (the
  container's `~`, re-seeded from the image) while keeping the workspace defined
  — config, token, and state survive, and bind-mounted host dirs are untouched.
  It destroys data, so on the loose surface it prompts for an implicit default
  (`--yes` bypasses).

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
