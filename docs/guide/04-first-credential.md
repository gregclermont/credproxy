← [03 · Daily workflow](03-daily-workflow.md) · [index](../README.md) · [05 · Secret managers](05-secret-managers.md) →

# 04 · Your first credential

This is the payoff. You will make a real GitHub token work inside the workspace
while the token itself never enters the container. The proxy holds the real
value and swaps it in for you.

## The idea in one sentence

Your tool must send *some* token to `api.github.com`, but you do not want the
real one inside the container. So the workspace holds a
[placeholder](../concepts.md#placeholder) — a fake token of the right shape — and
the [proxy](../concepts.md#proxy) swaps it for the real one on the way out.

## Add the binding

You will use two pieces:

- A [provider](../concepts.md#provider) — where the real value comes from. Here,
  `env` reads a host environment variable.
- An [injector](../concepts.md#injector) — how the value is sent. Here, `bearer`
  sends it as an `Authorization: Bearer` header.

Together with a host, they form a [binding](../concepts.md#binding). Put your
real token in a host environment variable, then create the binding:

```sh
export GITHUB_TOKEN=ghp_your_real_token          # a real token, on the HOST
credp binding add \
    --injector bearer --provider env --secret GITHUB_TOKEN \
    --host api.github.com --env GITHUB_TOKEN
```

```console
$ credp binding add --injector bearer --provider env --secret GITHUB_TOKEN --host api.github.com --env GITHUB_TOKEN
added binding 'bearer-env' to workspace 'myproject'
  injector    bearer
  provider    env
  secret      GITHUB_TOKEN
  hosts       api.github.com
  placeholder credproxy_AOFWLTeyzi8jUF1YTApGxjlCpXn62z
  env         GITHUB_TOKEN
```

credproxy generated a placeholder for you. `--secret GITHUB_TOKEN` is the *name*
of the host variable to read (not the value), and `--env GITHUB_TOKEN` is the
variable name the workspace will learn the placeholder under.

> [!IMPORTANT]
> The real token stays on your host. `credp` reads it only when it pushes the
> resolved configuration to the proxy. It is never written into the workspace
> container.

> [!TIP]
> Don't remember all the flags? On the `credp` surface in a terminal, run
> `credp binding add` with the missing pieces omitted and it walks you through
> them — an injector picker (`bearer` preselected), a provider picker, the secret
> ref (with an offered validate-now fetch), and one or more hosts (each checked as
> you type). It then echoes the equivalent fully-flagged command so you learn it
> for next time. The strict `credproxy` surface never prompts — it fails with the
> list of missing flags instead, so scripts stay predictable.

## Apply it

The binding is in your config file. Push it to the running proxy:

```sh
credp start
```

`start` re-resolves every secret and re-pushes the configuration, then continues
if the containers are already up.

## Prove it from inside

Enter the workspace. The real token is nowhere in this container, yet the call
to GitHub succeeds — and because you gave the binding an `--env`, the placeholder
is *already* in `$GITHUB_TOKEN` (a login shell reads `/etc/profile.d`, which
pulls in `/exports.sh`):

```console
$ credp enter
vscode@myproject:~$ echo "$GITHUB_TOKEN"
credproxy_AOFWLTeyzi8jUF1YTApGxjlCpXn62z
vscode@myproject:~$ curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user | jq .login
"your-github-username"
```

The value in `GITHUB_TOKEN` is the placeholder. When the request left the
container, the proxy recognized the placeholder on a request to `api.github.com`
and replaced it with your real token. GitHub saw the real token and answered.

> [!NOTE]
> The proxy advertises each binding's placeholder and its suggested variable
> name at `http://proxy.local/setup`, where `bindings` is an object keyed by
> name — `curl -s http://proxy.local/setup | jq -r '.bindings["bearer-env"].placeholder'`
> returns this binding's placeholder. That endpoint is how a tool learns what to
> send; the login-shell export above is the convenience built on top of it.

## Watch the swap

Open a second terminal on the host and stream the audit log while you run the
`curl` again:

```console
$ credp logs --audit
2026-07-05T18:30:12Z  audit inject    GET api.github.com/user  'bearer-env' injected
```

*(Sample output.)* The audit record names the binding, the host, and the method
— never the secret value. It is proof the swap happened, safe to keep.

> [!WARNING]
> If GitHub returns `401`, the binding did not fire. The most common cause is
> sending the placeholder in the wrong place, or to a host the binding does not
> cover. The `credp logs` stream shows the reason.

## You did it

One real credential now works inside a container that never holds it. Everything
else builds on this: more services, real secret managers, and guardrails.

> [!TIP]
> The `env` provider is the simplest source, but your secrets probably live in
> 1Password, the macOS Keychain, or your `gh` login. Swapping the provider is a
> one-flag change → [05 · Secret managers](05-secret-managers.md). To wire a
> whole service (all of GitHub's hosts) in one command →
> [06 · Packs](06-packs.md).

---

**Next:** [05 · Secret managers](05-secret-managers.md) — pull credentials from
1Password, the Keychain, and more.
