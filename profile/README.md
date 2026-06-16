# Distribution profile (org overlay)

This directory is the **profile overlay**: the middle tier of credproxy's
resolution chain, between an end user's personal config and the in-package
upstream defaults:

```
user ($XDG_CONFIG_HOME/credproxy)  →  profile (this dir)  →  builtin (upstream)
```

It's how an **org or fork customizes credproxy without touching engine code**.
Everything here is data; upstream ships this directory empty (just this README),
so a fork only ever *adds* files and never conflicts on `git merge upstream`.
Your entire diff against upstream lives here.

You don't have to fork at all: set **`CREDPROXY_PROFILE_DIR`** to point at any
directory (a deb/rpm payload, a git submodule, `/etc/credproxy/profile`) with
this same layout, and the CLI uses it as the overlay.

## What you can put here

| File / dir | Overrides | Effect |
|---|---|---|
| `workspace.template.toml` | the builtin scaffold | the `<name>.toml` a fresh `credproxy create` produces — your canonical default workspace (image, user, setup, even default `[[binding]]` blocks). |
| `injectors/<name>.toml` | a builtin injector of the same name (or new) | a request-shaping scheme. |
| `providers/<name>` | a builtin provider | a secret source executable. |
| `scripts/<name>.star` | a builtin script | a sandboxed Starlark injector body. |
| `presets/<name>.toml` | a builtin preset | a coordinated multi-binding set (e.g. your internal registry). |

A same-named file **shadows** the builtin one; a new name **adds** to it. A user
file under `$XDG_CONFIG_HOME/credproxy/` still shadows the profile in turn.

See the builtin defaults under `cli/credproxy_cli/builtin/` for complete worked
copies. Full guide: [`docs/forking.md`](../docs/forking.md).

## `workspace.template.toml` note

The scaffold is a **literal workspace config** — its `image`, `user`, `home`,
`setup` are concrete values. credproxy substitutes only `{name}` (used in the
header comment), so **double any other literal braces** (`{{ ... }}`). The
proxy image tag and the workspace image are not separate knobs: the workspace
image is just the `image` line here, and the proxy image tag is fixed in the
engine. To run a different workspace image, edit `image` (and `user`/`home` to
match) in your template — or, per workspace, in the generated `<name>.toml`.
