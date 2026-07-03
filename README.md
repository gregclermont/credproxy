# credproxy

credproxy runs a persistent, named workspace (container) whose outbound network passes through a per-workspace credential-injecting proxy. The proxy holds the real secrets; the workspace holds only inert placeholder tokens that are format-valid for each service. When the workspace sends a request to an approved host, the proxy substitutes the placeholder for the real credential before forwarding — so an agent or tool inside the workspace authenticates normally while the actual secret never enters the container.

## Quickstart

```sh
# 1. Build the proxy image (needs the repo checkout)
./bin/credproxy dev build

# 2. Create a workspace (scaffolds a config file; edit it for image/mounts/env)
./bin/credproxy workspace create myproj

# 3. Add a credential binding (a GitHub PAT spans bearer + basic hosts, so use
#    the preset; for a single host/scheme use `--injector bearer --host H`)
./bin/credproxy workspace myproj binding add \
    --preset github --provider env --secret GITHUB_TOKEN

# 4. Start the workspace (resolves secrets, pushes config, starts containers)
./bin/credproxy workspace myproj start

# 5. Enter the workspace
./bin/credproxy workspace myproj enter
```

Inside the workspace, bootstrap the CA and fetch the placeholder bindings:

```sh
curl -sSL http://proxy.local/bootstrap.sh | sh
curl -s http://proxy.local/setup | jq .bindings
```

## The two surfaces

`credproxy` is the strict, scriptable surface: every workspace is named explicitly, no defaults, no prompts. Use it in scripts and docs.

`credp` is the human alias (`credproxy --loose`): resolves an omitted workspace from the current default, adds short aliases (`credp enter`, `credp use myproj`), and gates destructive implicit actions behind a confirmation prompt.

Both surfaces share the same core; `--json` is available on either for machine-readable output.

## Further reading

- `docs/configuration.md` — workspace config: the TOML file format and the CLI that edits it
- `docs/workspace.md` — netns constraints, bootstrap guide, egress shape
- `docs/injectors.md` — injector TOML format (how a credential is shaped into a request)
- `docs/rules.md` — rules: block/stub/rewrite/script traffic on intercepted hosts (a credential-free guardrail; e.g. block `DELETE /repos/**`), with optional hidden rules as tripwires
- `docs/providers.md` — provider exec protocol (writing your own backend)
- `CLAUDE.md` — architecture guide for working on credproxy itself
