# Customizing credproxy for an org (the profile overlay)

An org or team often wants its own defaults: a standard workspace image, an
internal CA in every container's setup, a vault provider, an artifact-registry
preset. credproxy is built so you can do all of that **without editing engine
code** — and, ideally, without maintaining a code fork at all.

## The three tiers

Every customizable asset resolves through one ordered search path, most specific
first:

```
user            $XDG_CONFIG_HOME/credproxy/   per-machine, the end user
  ↓ shadows
profile          $CREDPROXY_PROFILE_DIR or <repo>/profile/   the org overlay
  ↓ shadows
builtin          cli/credproxy_cli/builtin/   upstream defaults (in-package)
```

A same-named file in a higher tier **shadows** the lower one; a new name **adds**
to the set. This is `paths.layered_dirs()` for the registries (injectors,
providers, scripts, presets) and `paths.resolve_singleton()` for the one
singleton, `workspace.template.toml`.

## Two ways to customize

### 1. Point at a profile bundle — no fork (recommended)

Set `CREDPROXY_PROFILE_DIR` to any directory with the layout below — a deb/rpm
payload, a git submodule, `/etc/credproxy/profile`, a dotfiles dir:

```sh
export CREDPROXY_PROFILE_DIR=/etc/credproxy/profile
```

Nothing to merge: you ship the overlay as data, on whatever cadence you like, and
track upstream credproxy unmodified.

### 2. Fork the repo

Commit your customizations under `profile/` (which upstream ships empty except a
README). Your **entire diff against upstream lives in `profile/`**, and upstream
never writes there, so `git merge upstream/main` is conflict-free in perpetuity.
The engine and builtin defaults you inherit; your overlay you own.

## What you can put in the overlay

```
<profile>/
  workspace.template.toml      # the scaffold a fresh `create` produces
  injectors/<name>.toml        # request-shaping schemes
  providers/<name>             # secret-source executables
  scripts/<name>.star          # sandboxed Starlark injector bodies
  presets/<name>.toml          # coordinated multi-binding sets
```

> The proxy image tag and the `home` fallback are fixed engine constants (not
> customizable for now), and there is **no default *workspace* image knob** — the
> default workspace image is simply the `image` line in `workspace.template.toml`.

### `workspace.template.toml` — the scaffold

The `<name>.toml` body a fresh `credproxy create` writes. Make it your canonical
default workspace — your image, your `user`/`home`, your `setup`, even default
`[[binding]]` blocks for org infrastructure. It's a **literal** workspace config:
credproxy substitutes only `{name}` (used in the header comment), so **double any
other literal braces** (`{{ ... }}`). To run a different image, edit `image` (and
`user`/`home` to match) here, or per workspace in the generated `<name>.toml`.

### Registries — injectors / providers / scripts / presets

Drop a `<name>.toml` (or executable, or `.star`) in the matching subdir. Same
name as a builtin one **replaces** it; a new name **adds** it. The shapes match
the builtin examples — see [`injectors.md`](injectors.md),
[`providers.md`](providers.md), and `cli/credproxy_cli/builtin/presets/github.toml`.

## Shipping static files (profile mounts)

Beyond the registries, an overlay can hold **arbitrary static files** — a CA
cert, an `.npmrc`, a `.gitconfig`, a setup script — and mount them into every
workspace. In `workspace.template.toml` (or a workspace's `mounts`), a
`{ profile = "REL", target = "/dst" }` mount binds a path **relative to the
profile dir** into the container (confined within the profile dir, read-only by
default). So the overlay becomes a self-contained bundle: declarative config
*and* the static assets it references. See
[`configuration.md`](configuration.md) `mounts`.

## Precedence and testing

A user's `$XDG_CONFIG_HOME/credproxy/` file still wins over the profile overlay,
so an individual can override an org default locally. To verify an overlay in
place, point `CREDPROXY_PROFILE_DIR` at it and run `credproxy injector list`,
`credproxy preset list`, `credproxy config`, or `credproxy workspace create … &&
credproxy workspace … config --declared`.
