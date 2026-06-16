# design-mounts.md — unified mounts, managed volumes, optional home

**Status:** **implemented** (recommended set: G3 grammar, generalized host-bind
chown, `home` as sugar (H2), `delete --keep-volumes` / D1, `recreate
--reset-volume NAME` / R2). Supersedes the bind-only `mounts` and the bespoke
`home` volume. Builds on the profile overlay (`docs/forking.md`). The reference
below records the design; the code (`core/config.py`, `core/lifecycle.py`,
`core/workspace.py`, `porcelain/cli.py`) is the source of truth.

## Why

Today:
- `mounts = ["SRC:DST[:ro]"]` — **host bind mounts only**.
- `home = "/path"` — a bespoke, credproxy-managed **named volume** mounted there,
  image-seeded, the chown-safety anchor, removed on `delete`.

Gaps:
1. **No named volumes** — no cache/scratch persistence without a host dir; bad
   bind-mount perf on Docker Desktop macOS; binds drag in the uid/ownership dance.
2. **No way to ship static files** (config/scripts/certs) alongside a profile and
   mount them in — the profile can't be a self-contained bundle.
3. `home` is a **special code path**; "optional persistent home" is awkward.
4. chown safety is **anchored on `home`** rather than on the real invariant.

Goal: one mount model with three source kinds, a host-bind-aware chown rule, a
managed-volume lifecycle, and `home` as just a managed volume (→ optional home
for free).

## 1. Mount source kinds (grammar)

Three source kinds. No users yet, so the grammar is chosen purely on merit.

| Kind | Source resolution |
|---|---|
| host **bind** | `~` expanded; must be absolute; must exist |
| managed **volume** | `NAME` namespaced per workspace; image-seeded; ownership-clean |
| **profile-relative** bind | resolved under `profile_dir()`; confined (no `..` escape); must exist; default `:ro` |

**Recommended form — strings are binds, typed kinds are inline tables (G3):**

```toml
mounts = [
  "~/code:/code",                                              # host bind
  "/etc/ssl/certs:/certs:ro",                                  # host bind
  { volume = "build-cache", target = "/home/vscode/.cache" },  # managed volume
  { profile = "gitconfig", target = "/home/vscode/.gitconfig", readonly = true },
]
```

The common case (a bind) stays terse and `docker -v`-familiar; the typed kinds
are explicit, self-documenting tables — no colon-splitting fragility, no source
sigils. A heterogeneous string/table array is valid TOML.

**Grammar alternatives:**
- **G1 — sigil strings only:** `"volume:NAME:/dst"`, `"profile:rel:/dst"`, bind
  otherwise. Terse and uniform, but packs the kind into a string and the
  `SRC:DST:ro` split is fragile (a source containing `:`).
- **G2 — tables only:** every entry a table (`{ bind = "~/code", target = … }`).
  Maximally uniform and explicit; verbose for the overwhelmingly-common bind.

G3 is the recommendation (terse where it's common, explicit where it's not); G2
if uniformity is valued over bind terseness.

## 2. chown: host-bind-aware (replaces the home anchor)

**Invariant:** a fabricated mount-parent dir is re-owned to the workspace `user`
**iff it is not inside a host bind mount** — a managed volume or the container's
own writable layer is host-safe; a host bind is never touched (the load-bearing
"credproxy never changes host-file ownership" promise).

- Runs only under `map_host_user` + `user` (as today); idempotent.
- Per mount target, the runtime fabricates root-owned parents that don't exist in
  the image and aren't themselves mounts; for each, find the nearest enclosing
  mount and skip if it's a host bind, else chown.
- `home` loses its special role — it's just one chown-safe managed volume. The
  current "under the home volume" rule is the common special case of this.
- **Alternative:** drop the chown entirely (users `chown` in `setup` when they
  nest a mount under a non-root-owned volume). Less magic, more user burden.
  Recommend generalize.

## 3. Managed-volume lifecycle

A `volume:` mount (including `home`) gets a per-workspace namespaced Docker
volume (`credproxy-<workspace>-<name>`).

- **create:** lazily on first `start` (Docker auto-creates a named volume on the
  first `-v`); seeded from the image's content at the target path.
- **stop / recreate:** survive — data persists (the point of `recreate`).
- **delete / reset:** see *UX options* below.
- **spec hash:** includes the mount *declarations* (changing them recreates the
  container); volume *contents* are not hashed.

## 4. `home` is just a managed volume

After §2–§3, `home` carries no special semantics — it's a managed volume mount.
Two ways to express it (a real design choice now, not a compat question):

- **H1 — no `home` field.** The scaffold simply declares the volume + workdir:
  ```toml
  mounts = [{ volume = "home", target = "/home/vscode" }]
  workdir = "/home/vscode"
  ```
  Maximally uniform — home is nothing special. Cost: the path appears twice
  (mount target + workdir), and there's no field that names "the home dir."
- **H2 *(rec)* — keep a `home = "/path"` field as pure sugar.** It expands to
  `{ volume = "home", target = "/path" }` *and* defaults `workdir` to `/path`.
  Not a special code path — it desugars into the uniform mount machinery — but it
  keeps the near-universal case DRY (the path once) and names the intent. Worth
  it on ergonomics alone, independent of compatibility.

Either way:
- **Optional home:** drop the home volume (omit the `home` field / its mount) →
  the container's home is the image's, ephemeral (gone on recreate). The deferred
  "optional persistent home," for free.
- **workdir:** defaults to the home target if a home is configured, else the
  image `WORKDIR`. (Or: always image WORKDIR, set `workdir` explicitly — simpler,
  but loses "land in home.")
- **The hard constraint:** home must be a *volume*, not a bind. Volumes image-seed
  (so `/home/vscode` keeps the image's pre-created, owned dotfiles) and are
  chown-safe; a bind home loses seeding and re-introduces the host-ownership
  violation. That's a mount-*type* property, uniform across all mounts.

## 5. Concrete changes

- `core/config.py load_config`: parse mounts into typed records
  (`kind`/`source|name`/`target`/`readonly`); resolve `~` (bind), namespace
  volume names, resolve + confine `profile:` paths, validate existence
  (bind/profile); synthesize the `home` record from the sugar.
- `core/lifecycle.py create_ws_container`: emit `-v` per record — bind
  `host:tgt[:ro]`, volume `<ns>:tgt[:ro]`, profile `<resolved-host>:tgt[:ro]`;
  SELinux relabel on binds as today.
- chown: replace `chown_mount_parents` / `_mount_parent_dirs` with the
  host-bind-aware pass.
- `delete_workspace` / `recreate_workspace`: per the UX options below.
- spec hash: include the typed mount list (subsumes the `home` + `mounts` fields).
- `map_host_user`: re-express its `home` references against the home *volume*
  record.

## 6. Adoption

No users yet, so there's nothing to migrate — land the design directly:
- Rewrite the builtin `workspace.template.toml` to the chosen grammar (the home
  volume + `workdir`, plus commented `volume:`/`profile:` examples).
- Replace the `home`/`mounts` parsing + `chown_mount_parents` + the home-volume
  lifecycle in one pass; update tests/docs to match. No compat shims or aliases.

---

## Open decisions

1. Grammar: G3 strings-are-binds + typed tables *(rec)* / G1 sigil-strings / G2 tables-only.
2. chown: generalize to the host-bind invariant *(rec)* vs drop.
3. `home`: H2 keep as ergonomic sugar *(rec)* vs H1 no field (explicit volume + workdir).
4. workdir default: home-else-image `WORKDIR` *(rec)* vs always-image.
5. **Delete UX** — below (rec D1 + `--keep-volumes`).
6. **Reset UX** — below (rec R2).

### Delete UX — what happens to a workspace's managed volumes on `delete`?

| | Behavior | Pro | Con |
|---|---|---|---|
| **D1** *(rec)* | Wipe all the workspace's managed volumes (generalizes today's home) | Simple; "delete means gone"; consistent (home isn't special); volumes are per-workspace so nothing shared is hit | A cache you might've salvaged is destroyed — but `delete` is already a gated, high-cost op run on purpose |
| **D2** | Wipe by default; `--keep-volumes` preserves them | Salvage hatch | Preserved volumes become orphans (`credproxy-<ws>-…` with no workspace) needing later cleanup |
| **D3** | Keep volumes by default; `--purge`/`--volumes` also wipes | Safest — never lose data unasked | Orphans accumulate silently; inconsistent with "delete removes everything" and with today's home |

**Recommendation: D1 + a `--keep-volumes` flag** (so the default is D1, the
flag opts into D2). Extend the existing loose-surface destructive prompt to name
what's wiped ("delete workspace X **and N volume(s)**?"). Gated, consistent,
with a salvage hatch. (Orphans from `--keep-volumes` argue for a future `volume`
subcommand — see R4.)

### Reset UX — wiping a volume's *contents* without deleting the workspace (generalizes `recreate --reset-home`)

| | Behavior | Pro | Con |
|---|---|---|---|
| **R1** | `recreate --reset-volumes` wipes ALL managed volumes | One flag; "fresh data everywhere" | Blunt — can't reset just the cache |
| **R2** *(rec)* | `recreate --reset-volume NAME` (repeatable) | Granular + targeted; resetting home is just `--reset-volume home` | Must name volumes |
| **R3** | R2 **plus** `--reset-volumes` (all) | Granular + a "reset everything" convenience | Two flags for one concept |
| **R4** | A `credproxy workspace NAME volume {list\|reset NAME\|rm NAME}` subcommand; `recreate` stays purely about containers | Cleanest separation; scales (sizes, prune); explicit | More surface; `reset` overlaps recreate's stop→wipe→start |

**Recommendation: R2** — `recreate --reset-volume NAME` (repeatable). The old
`--reset-home` flag goes away entirely; resetting the home volume is just
`--reset-volume home`. Add `--reset-volumes` (R3) only if "reset everything"
proves common. Defer R4 (a `volume` subcommand) as the future home for richer
volume management (list/sizes/prune). Reset stays gated (it destroys data).
