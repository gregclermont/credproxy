# credproxy — Design Specification

**A CLI for running coding agents in sandboxed, persistent workspaces behind a credential-injecting proxy.**

This document captures the design decisions from a working session: the conceptual model, the security architecture, the command-line interface, and the implementation shape. Items that were explicitly deferred are listed at the end.

---

## Overview

credproxy runs a CLI coding agent inside an isolated container whose outbound network passes through a per-workspace proxy. The proxy injects credentials into requests to approved services, so the agent can authenticate to the things it needs **without the real secrets ever entering the container**.

The same person configures and runs the tool — there is no separate operator role.

Agents are the *motivation* for the tool but are **not a first-class concept** in the CLI. The tool's job is narrower and more durable: provide persistent, named, sandboxed environments with a credential-injecting proxy in front. Whatever agent you run is just a command you invoke inside.

---

## Guiding principles

These recur throughout the design and explain most of the specific choices:

- **No hidden state; honesty over magic.** Behavior is predictable; where something is implicit or deferred, the tool says so.
- **The config file is the single source of truth.** Imperative commands are sugar that edit it; every command has a config-file equivalent.
- **Substrate + conveniences.** A complete, strict, explicit contract underneath; human conveniences layered on top. The same pattern appears in canonical-commands-vs-aliases, structured-output-vs-human-rendering, the default-workspace mechanism, and the `credproxy`/`credp` split.
- **Least privilege, least disclosure.** The sandbox can observe and use, never reconfigure; secrets never enter it; the inward API exposes only what self-configuration needs.
- **Cost of recovery drives safety.** Confirmation gates appear where a mistake is expensive to undo, not merely where it is "destructive."

---

## Core concepts

**Workspace** — a persistent, named environment you return to, tied to one or more project directories via bind mounts. It can be stopped and restarted across days; it is "an identified place to do work." It is realized as a *pair* of containers — the workspace container and its own proxy container — but that pairing is an implementation detail; the noun "workspace" deliberately sits above it. (This is precisely why the noun is "workspace" and not "container": there are two containers, and the user-facing concept must not be ambiguous.)

A workspace is identified by a **name** (the handle you use to refer to it) and recognized by its **bind-mount paths** (the cue that tells you which project it belongs to).

**Injector** — defines *how* a credential is shaped into a request for a particular service (which header, what format). Service-specific, passive, reusable. The tool ships injectors for common services; you can author your own.

**Provider** — defines *where* a credential value comes from: a secret backend (a vault, an environment variable, a script, etc.). Pluggable, passive, reusable. Bundled ones plus your own.

**Binding** — a workspace-owned tie that connects the above into one usable, scoped credential. Its anatomy:

```
name · injector · provider · secret-id · placeholder · hostname scope
```

- **name** — a unique handle for the binding (used to remove or test it). Auto-generated from the injector + provider names, with a numeric suffix on collision; overridable. Must be unique because it is part of addressing.
- **injector** — which injector shapes the request.
- **provider** — which backend supplies the value.
- **secret-id** — *which* secret within that provider. An opaque, provider-interpreted reference (a vault path, an env var name, an item ref).
- **placeholder** — the inert sentinel the workspace holds and the agent sends; the proxy swaps it for the real value (see the security model).
- **hostname scope** — the host(s) for which injection is permitted. A security boundary.

Workspaces, injectors, and providers are all managed **centrally** (not per-project), which is what allows a single workspace to bind-mount several projects and reference shared definitions.

---

## Security model

This is the core of the tool.

**Per-workspace proxy.** Each workspace has its own proxy, holding only that workspace's credentials. The blast radius of any bug is a single workspace, and there is no cross-workspace routing or shared secret store. It also makes running many workspaces at once cheap and fully independent.

**Hostname-scoped injection.** A binding's credential is only injected on requests to its approved hosts. This prevents the agent (or a compromised dependency) from exfiltrating a secret by sending it to an unrelated or malicious host.

**The placeholder mechanism.** The real secret **never enters the workspace.** Instead:

1. The injector generates a **placeholder** — an inert sentinel that is *format-valid for the service* (right prefix, length, character set), so it passes any client-side token validation. It is generated once when the binding is created and stored statically (so the agent's environment and the proxy's expectation never drift); it can be overridden.
2. The workspace exposes the placeholder to the agent (e.g., as an env var).
3. The agent sends requests carrying the placeholder. For requests to an **approved host**, the proxy substitutes the placeholder with the real value fetched from the provider, shaped by the injector, and forwards the authenticated request.

Two attack vectors are closed, and they compose:

- Agent sends the placeholder to a **disallowed host** → the proxy does not substitute → the host receives a meaningless sentinel, not the secret.
- Agent reads its **own environment** to exfiltrate the credential → it finds only the placeholder.

In effect, a binding is **the proxy's mapping across the trust boundary**: workspace placeholder ⟷ provider secret-id, shaped by the injector, gated by the scope.

**The door model.** The control plane lives *outside* the sandbox. From inside a workspace you can **observe and use**, never **configure** — you cannot add a binding, widen a scope, or read a real secret from within.

**Inward API.** A read-only HTTP API is exposed *inside* the workspace, served by the proxy, listing the workspace's bindings with their placeholder values, so the agent (or a setup script, or the user) can wire each tool up however it expects. It is safe to expose precisely *because* placeholders are inert. It follows **least disclosure**: it returns only what self-configuration needs — binding name, placeholder value, the request header and scoped hosts the placeholder applies to, and an optional suggested env var — and withholds the provider and secret-id (where the real secret lives has no use for self-configuration and should not be enumerable from inside). This is a **pull** model; an optional **push** convenience (the tool auto-setting conventional env vars) can sit on top, consuming the same data.

So the proxy is the agent's entire interface to credentials: requests flow *through* it (data plane, where substitution happens) and it can be *queried* for placeholders (introspection). Defining bindings stays outside (control plane).

*(TLS interception is the implementation mechanism that lets the proxy substitute inside HTTPS traffic; it and container orchestration are implementation concerns, out of scope here.)*

---

## Extensibility

Injectors, providers, and secret sourcing are all **pluggable and filesystem-native**: drop a definition in a known directory, reference it by name. The filesystem *is* the registry — no package manager, no central registry — which makes extensions trivially shareable (they are just files). Listing and shell completion are progressive enhancements, not load-bearing.

The tool ships bundled injectors and providers that double as templates (starting points); `scaffold` copies one into your directory to author from.

The **injector/provider authoring contract** — what a definition file actually implements (inject-transform, generate-placeholder, format and env-var hints) — is a separable sub-design and is *not* specified here.

---

## Configuration & state

**Config file as source of truth.** Each entity is a file you can hand-edit (a first-class path), and imperative commands are sugar that edit the same file. Every imperative action has a config-file equivalent; there is no hidden state.

**Central storage, TOML, one file per workspace** (name = filename). The config schema mirrors the command flags, keeping the declarative and imperative paths in lockstep.

Workspace config example:

```toml
image  = "..."
mounts = ["~/code:/code"]
env    = { GH_DEBUG = "1" }
setup  = ["npm ci"]

[[binding]]
name     = "github-vault"     # auto-generated if omitted
injector = "github"
provider = "vault"
secret   = "github/pat"
hosts    = ["api.github.com"]
# placeholder + env auto-generated by the injector; override here only if needed
```

Directory layout (XDG-style):

```
~/.config/credproxy/
  workspaces/   myproj.toml        # one file per workspace
  injectors/    github/  …         # bundled + your own, drop-in
  providers/    vault/   …         # bundled + your own, drop-in
```

Runtime state — running containers, the current-default pointer — lives separately under a state directory.

**Apply is best-effort with honest reporting.** A file edit is not picked up automatically; you `apply` it (or restart). The tool applies what it can to the running workspace live, defers what it can't, and reports what happened. **Drift** is first-class: `inspect` shows whether the running state matches the config and what differs.

**The current default workspace** is stored in a global file (it persists across shells). Its footgun is mitigated by three layers: the default is marked in `list`, destructive-and-implicit commands require confirmation, and `--yes` bypasses for scripts (see Safety).

Container-side settings (base image, bind mounts, env vars, setup commands) all have sensible defaults and are edited in the file after creation; only bindings are addressable by command. Settings belong to the workspace and persist with it — there is no global-defaults layer.

---

## Lifecycle

Workspaces are long-lived. The **hot path** is *entering* an existing workspace — getting a shell inside, then running an agent (or anything else) in it.

**Multiple workspaces run independently**, each with its own proxy and no shared state. Start and stop are **explicit, user-managed states** ("stopped but exists" is the normal state a workspace is in before you return to it). An optional **per-workspace auto-stop** policy is available but off by default, since there are good reasons to keep one running (a background process, a faster next session). Because auto-stop is just config, changing it mid-session is a live config edit like any other.

---

## Command-line interface

**Structure: hybrid noun-first.** Every entity has a full canonical form (`<tool> <entity> <verb> …`); the common path also gets short aliases. Canonical forms are the *contract* — stable, complete, what scripts and docs target; aliases *resolve to* canonical commands with no independent behavior.

**Addressability is selective.** The workspace is the primary addressable unit; its **bindings** are individually addressable *through* their owning workspace (the security-critical, frequently-tuned part). Other container-side config is file-only.

**Multi-entity actions resolve by ownership.** A command is attributed to the entity that *owns* the result; independent entities ride along as named references. A binding is workspace-owned, so binding commands are workspace-attributed, with the injector and provider named as references.

**Verb-tier convention.** `create` / `delete` for top-level entities; `add` / `remove` for items inside a workspace. The verb signals the tier — you *create* a workspace, you *add* a binding to it.

**Default workspace (human layer only).** When the workspace is omitted, the current default is used; the resolved entity is announced, and the current selection is always inspectable. Scripts always name the workspace explicitly.

**Argument shape.** The primary entity is positional and optional (omit → default). A binding's references are **named flags** — this is the security-sensitive command, and positional ordering on a hostname boundary is exactly where a silent mistake would be dangerous.

### Operations

**Workspace:** `create` · `enter` (hot path) · `start` · `stop` · `list` (with filter; marks the current default) · `delete` · `apply` (reconcile edited config → running) · `inspect` (config + state + drift) · `logs` (proxy activity, for debugging injection).

**Binding** (through a workspace): `add` · `remove` · `list` · `test` (dry-run — both a bound-in-context test and a standalone test of a definition before it is bound).

**Injector / provider:** `scaffold` (starter from a bundled template) · `list` (progressive enhancement).

**Meta:** `use` (select the default workspace) · show current.

### Example invocations

```
# make a workspace — scaffolds config from defaults; edit the file for image/mounts/env/setup
credproxy workspace create myproj

# enter it — canonical (explicit), the alias that assumes the default, the alias with explicit override
credproxy workspace myproj enter
credp enter
credp enter myproj

# pick the default
credproxy workspace use myproj

# add a binding — canonical, with named flags
credproxy workspace myproj binding add \
    --injector github --provider vault \
    --secret github/pat --host api.github.com

# the hot-path alias assumes the default workspace
credp binding add --injector github --provider vault --secret github/pat --host api.github.com

# survey / reconcile / debug
credproxy list                      # workspaces, current one marked
credproxy workspace myproj inspect  # config + running state + drift
credproxy workspace myproj apply    # push edited config onto the running workspace
credproxy workspace myproj logs     # proxy activity
```

**Binding flags:** `--injector` · `--provider` · `--secret` (the opaque provider ref) · `--host` (repeatable) — plus the defaulted optionals `--name`, `--placeholder`, `--env`.

---

## Safety behavior

Destructive commands that rely on an **implicit** target require interactive confirmation. The rule is **coupled to the hidden state**: it fires only when a command is *both* destructive *and* operating on an implicit target (the default workspace). An explicit destructive command does **not** prompt — naming the target is intent. The prompt surfaces what the implicit argument resolved to:

```
Delete workspace "myproj" (current default)? [y/N]
```

The **destructive set** is chosen by *cost of recovery*, not bare reversibility:

- **`delete`** — irreversible. Gated.
- **`binding remove`** — reversible, but loses tuning that took real work to get right. Gated.
- **`stop`** — excused; a restart is cheap.

The confirmation is a scoped exception to the otherwise non-interactive design: it is bypassable with `--yes`, and **fails closed** if it cannot read an answer (no terminal, no `--yes`) — it refuses rather than guessing. Together with the visible default marker in `list`, this forms a three-layer net: **visible default → explicit-or-confirm → `--yes` for scripts.**

---

## The two surfaces

The tool ships as **one binary with a mode flag and a shell alias**, embodying the substrate/wrapper split:

- **`credproxy`** — the strict, explicit, scriptable surface: the complete contract. Always names targets explicitly, no default-workspace magic, no prompts, structured output. The substrate.
- **`credp`** — a shell alias for `credproxy` with the convenience flag on: the human surface. Default workspace, `use`, aliases, the confirmation gate, human-rendered output. The reference wrapper.

**Strict is the default; the flag turns convenience on.** The reason is a safety asymmetry: if convenience were the default, a script that forgot the flag would inherit hidden-state dependence and prompt hazards — failing *unsafe* by omission. With strict as the default, forgetting the flag in a script yields the explicit, reproducible behavior you wanted anyway, and forgetting it interactively costs only verbosity — which the alias erases. So "human-first" lives **in the alias**, not in the bare binary's default. (The flag's name barely matters; almost no one types it — `credp` is the real human entry point.)

Because behavior is then determined purely by *which name you typed*, there is no need for terminal sniffing — no "it behaved differently in CI." Behavior = invocation.

---

## Implementation architecture

A two-layer split *in code* keeps the engine free of convenience edge cases without needing two binaries:

- **Core** — takes fully-explicit, already-validated inputs (every workspace named, no defaults, no ambiguity), does the real work (containers, proxy, bindings), and returns **structured data**. It knows nothing about sugar and does no formatting.
- **Porcelain** — resolves all convenience (the default workspace into a concrete name, aliases, prompts, human rendering) and *then* calls the core with explicit inputs.

The discipline that keeps the core pristine: **the porcelain resolves every convenience to explicit before crossing into the core.** The core never sees "the default," only concrete names, so convenience edge cases live entirely in front of the boundary. Dependency runs one way: porcelain → core. The two modes are two thin front-ends over the *same* core — strict a near pass-through, loose the full porcelain — with no duplication of the real work. This is the exact boundary a two-binary split would draw, so splitting later (if ever) is a deployment decision, not a rewrite.

**Output.** Human-first by default, opt-in scriptable. Human output is a *rendering* of the same structured data the machine format emits. JSON output lives in the **presentation layer** and is **orthogonal** to the strict/loose axis: `--json` is its own flag, a sibling renderer to the human one, both fed by the core's structured result, available in *both* invocations (the mode only sets the default format). Two practical rules: in JSON mode **errors serialize as JSON too** (a structured error object on stdout — don't break a `jq` pipeline), and **streaming commands emit JSON-lines** (notably `logs`, one object per event).

---

## Naming reference

- **Entities:** workspace · injector · provider · binding
- **Verbs:** create · delete · list · start · stop · enter · apply · inspect · logs · add · remove · test · scaffold · use
- **Binaries:** `credproxy` (strict / scriptable) · `credp` (human alias)

---

## Deferred / out of scope

- **Injector/provider authoring contract** — the internal interface a definition implements (inject-transform, generate-placeholder, format + env-var hints). A separable sub-design.
- **Push delivery convenience** — optional auto-setting of conventional env vars, layered on the pull API.
- **Implementation** — TLS interception (the mechanism behind HTTPS substitution) and container orchestration.