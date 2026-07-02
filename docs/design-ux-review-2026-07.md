# Design & UX review — July 2026

A full-project review of credproxy's design and user experience: the CLI
surface, the proxy runtime's operational behavior, the configuration-authoring
experience (workspace TOML + the injector/provider/preset/script registries),
and the documentation/onboarding path. Findings reference `file:line` against
commit `f19022c`. The twelve highest-impact findings were filed as issues
[#15](https://github.com/gregclermont/credproxy/issues/15)–[#26](https://github.com/gregclermont/credproxy/issues/26)
and are cross-referenced below; everything else in this document is the long
tail — real, but fine to pick up opportunistically.

## Overall assessment

This is an unusually well-considered project. The architecture is coherent and
the hard design calls — the strict/loose CLI split, the push model, the
TOML-as-single-source-of-truth with surgical comment-preserving edits, the
fail-closed re-seal path, least-disclosure `/setup` — are made deliberately and
hold up under scrutiny.

The dominant weakness is a single theme repeating at every layer: **the happy
path is polished, but the most likely failure at each seam is the least
diagnosable.**

- A new user without Docker gets a raw Python traceback (#16).
- A user whose placeholder silently isn't replaced gets an upstream 401 with
  no breadcrumb on either side of the proxy (#15).
- A hand-edited typo in the workspace TOML is silently ignored (#17).

Fixing those three seams is worth more than any feature. The secondary theme
is **discoverability lag**: several excellent tools exist (`injector check
--compile`, the scripted-injector scaffold, `info`'s tier breakdown) that the
documentation doesn't yet mention.

## What's genuinely strong (the quality bar)

These should be treated as the standard the rest of the surface is measured
against:

- **Config-push validation** (`proxy/config.py:302-520`): every bad config
  400s with a path-qualified, actionable message — duplicate names, bad host
  patterns, unknown scheme with the full valid list, slot mismatches naming
  expected-vs-got, and the subtle placeholder-substring-overlap collision with
  a clear explanation. The CLI mirrors the same shape (`{file}: field ...`
  errors, with indices for mounts).
- **stdout/stderr and `--json` discipline** (`cli/credproxy_cli/porcelain/render.py:7-14`):
  results → stdout; `[credproxy]`-prefixed progress → stderr; confirmation
  prompts on stderr so a `--json` stdout stream is never corrupted; errors
  serialize as `{"error": {"type", "message"}}`; `logs --json` emits
  JSON-lines; commands that can't be JSON (`enter`, `edit`) reject the flag
  with a stated reason.
- **Curated per-command help**: leaf argparse parsers deliberately suppress
  raw usage spew in favor of prose help that explains the *why* of each flag
  (`_BINDING_ADD_HELP` and friends, `cli.py:1171+`) — e.g. the note that for
  the `env` provider the ref is the host env var *name*, not the value.
- **Startup diagnostics**: a proxy that fails to come up inlines its exit code
  and last ~12 log lines into the error (`lifecycle.py:472-491`) instead of
  making the user run `logs` themselves.
- **Security-conscious details throughout**: query strings stripped from
  request logs (`addon.py:90-91`); script errors logged by exception type
  only so a script can't exfiltrate a secret to stdout; `binding test`
  reporting value length, never the value; mid-config-swap-safe re-seal
  binding tracking (`addon.py:74-81`); the zero-entropy placeholder guard
  with its rationale (`injectors.py:118-122`); the `_preserve_tty` restore
  around killed providers (`providers.py:46-87`).
- **`workspace.template.toml`** is the best single artifact in the repo —
  self-documenting, recreate-vs-exec semantics on nearly every field, and the
  "USING A DIFFERENT IMAGE?" callout anticipating the #1 edit.
- **Latent footguns already defused**: reserved-name collision checks (a
  workspace can't shadow a verb), `scaffold --help` not creating a file named
  `--help`, `--reset-volume` validated against declared volumes *before*
  anything is destroyed, `edit` re-validating after the editor exits.
- **`docs/providers.md`** is a clean, complete protocol spec; the `bw`
  provider is a model interactive+batch implementation.

## Top priorities (filed as issues)

| # | Area | Finding |
|---|------|---------|
| [#15](https://github.com/gregclermont/credproxy/issues/15) | proxy | `(no-inject)` is undiagnosable — log candidate binding + coarse decline reason (complements #2's opt-in tracing) |
| [#16](https://github.com/gregclermont/credproxy/issues/16) | cli | Missing `docker` binary → raw traceback; `DependencyError` exists (`errors.py:39-40`) and is never raised |
| [#17](https://github.com/gregclermont/credproxy/issues/17) | cli | Unknown top-level TOML keys silently ignored; `auto_stop` unvalidated (`"false"` is truthy → silently enables) |
| [#18](https://github.com/gregclermont/credproxy/issues/18) | cli | No `version` command / `--version` / `__version__` |
| [#19](https://github.com/gregclermont/credproxy/issues/19) | cli | No `doctor` — one-shot environment preflight + all-at-once config validation |
| [#20](https://github.com/gregclermont/credproxy/issues/20) | docs | README lacks requirements/install and the two-container mental model |
| [#21](https://github.com/gregclermont/credproxy/issues/21) | docs | No end-user security/threat-model doc (lives only in CLAUDE.md) |
| [#22](https://github.com/gregclermont/credproxy/issues/22) | docs | No troubleshooting guide (symptom → cause → fix) |
| [#23](https://github.com/gregclermont/credproxy/issues/23) | proxy | `/health` is liveness-only; CA readiness race with the bootstrap |
| [#24](https://github.com/gregclermont/credproxy/issues/24) | proxy | No durable, structured credential-use audit trail |
| [#25](https://github.com/gregclermont/credproxy/issues/25) | proxy | `/llms.txt` gaps: sign/re-seal/script guidance, IPv6+H3 drops, glob semantics, carrier caveat |
| [#26](https://github.com/gregclermont/credproxy/issues/26) | proxy | Starlark request-time failures are type-name-only; no opt-in dev diagnostics |

Suggested first batch: #15, #16, #17, #18, #20 — they close the worst gap at
every layer for modest effort. #19 (doctor) and #24 (audit log) are the two
larger design additions worth planning next.

---

## Detailed findings

### 1. First-run experience & CLI surface

**Docker-not-installed → traceback** (filed as #16). Every docker call is a
bare `subprocess.run(["docker", ...])` (`core/docker.py`, plus
`imageenv.py:29-31`, `do_logs`' `os.execvp`). `main()` catches only
`CredproxyError` (`cli.py:1636-1637`), so `FileNotFoundError` escapes.

**Empty inventory gives no next step.** `credproxy list` on a fresh machine
prints just `no workspaces` (`render.py:60`); same dead-ends for `no bindings
in workspace ...` (`render.py:311`), `no presets`, `no {kind}s`. The list case
is a prime teaching moment: suggest `no workspaces yet — create one with
'credproxy workspace create NAME'` (hint on stderr so `--json` stays clean).

**`credproxy workspace NAME --help` (name, no verb) degrades.** It routes to
`_verb_help(["--help"])`, whose fallback prints the literal `usage: credproxy
workspace NAME --help` (`cli.py:1376`), treating `--help` as the verb. When
the only token is a help flag, print the workspace verb menu instead.

**No `version`** (filed as #18) and **no `doctor`** (filed as #19).
`_META_COMMANDS = {"list", "current", "info"}` (`cli.py:63`).

**No shell completion.** The hand-rolled router precludes argcomplete for
free; for a surface this deep (nested nouns, many flags) a completion
generator would materially help discoverability.

**`mount` has only `add`** (`cli.py:1021-1032`). `binding` sets the
expectation of add/remove/list/test; removing a mount means hand-editing the
TOML. A `mount list`/`mount remove` pair would match the established mental
model.

**Typed errors collapse to exit 1.** `errors.py` defines eight error classes
explicitly so callers "can distinguish failure kinds without string-matching",
but `fail()` maps everything to `sys.exit(1)` (`render.py:535-540`). For the
surface sold as "the scriptable contract", a small stable exit-code table (or
documenting the `--json` `type` field as the contract) would be consistent
with the pitch.

**Surface-blind next-step hints.** Core/renderer hints hardcode the canonical
form even under `credp` (`run 'credproxy workspace {name} start'`,
`render.py:155`, `render.py:304`, `lifecycle.py:1177-1178`), while
`pointer.py:57,63` hints use the loose form. The renderer knows the surface
and could adapt the hint.

**Silent windows during slow operations.** `wait_for_ready` can block up to
15s after `starting proxy...` with no interim feedback
(`proxy_http.py:70`); the `mount add --preserve` capture prints one line
before a potentially large copy (`lifecycle.py:812`). Text-step progress is
otherwise good (each `start` phase narrates); these two are the only real
gaps.

**Calibration notes (defensible as-is, listed for completeness):**

- Loose `binding add` on an implicitly-resolved workspace is ungated (the
  destructive gate covers `delete`, `binding remove`, `recreate
  --reset-volume`). Reversible + resolution announced on stderr, so
  intentional — but it is the one implicit mutation with no speed bump.
- `binding add` names via `--name` while `binding remove`/`test` take the
  name positionally — defensible (add auto-generates), worth a deliberate
  note.
- The `workspace NAME binding add` noun-verb-noun depth is inherent to the
  model and well-routed; the loose aliases collapse it.

### 2. Configuration authoring (workspace TOML & bindings)

**Unknown top-level keys silently ignored; `auto_stop` unvalidated** (filed
as #17). The strongest hand-edit safety gap; the per-mount parser already
shows the fix pattern (`config.py:103-105`).

**`config.py` module docstring is actively wrong.** It declares `image`
optional-with-default and `home` defaulted (`config.py:8-9`) — both
contradict the implementation (`image` required, `config.py:157-162`; `home`
no default, `config.py:167-169`) — and still shows the pre-typed-mounts
string-only schema, omitting `directory`, `exec_flags`, `enter_prelude`,
`shell`, `auto_stop`, `user_owned`. Sync it or delete it in favor of
`docs/configuration.md` (which is correct).

**Slot errors don't teach the syntax.** The slot-mismatch error names both
sets (`bindings.py:243-248`: `needs secret slot(s) {access_key_id,
secret_access_key}, got {value}`) but not the fix; append the concrete form
(`expected: --secret access_key_id=REF --secret secret_access_key=REF`) — the
names are already in hand. Related: a mistyped slot name
(`--secret privatekey=REF` for `private_key`) falls through
`_parse_secret_args`' bare-`value` path (`cli.py:548-551`) and produces an
error that never echoes what the user typed; an "unknown slot" check when a
single `SLOT=REF` has an unrecognized LHS would be friendlier.

**Two spellings for a host bind.** String `"SRC:DST[:ro]"` vs table
`{ bind = ..., target = ... }` (`config.py:80-88` vs `:116-118`). Harmless;
one doc line saying the string form is the idiom would remove the "which do I
use?" tax.

**Template `{{ }}` escaping trap.** The template's doubled braces
(`workspace.template.toml:79-84`) are `create`-time `{name}`-substitution
escapes; a user copying a commented example into their *generated* file and
keeping the doubling gets literal `{{ }}`. One inline comment ("doubled braces
are template-only; write single braces in your file") closes it.

**Template shows only the `env`-provider binding shape.** The commented
example uses `injector = "bearer"` / `provider = "env"`; the README's
recommended path is `--preset github`. A second commented example showing the
preset form would align the two.

### 3. Proxy runtime & observability

**"Placeholder wasn't replaced" is nearly undiagnosable** (filed as #15; the
opt-in tracing counterpart is #2). `BasicScheme.on_request` alone has four
silent `False` paths collapsed into one `(no-inject)` marker
(`schemes.py:300-314`); partial fires (some bindings fired, others declined)
are invisible; and `addon.py:84` re-runs `creds.intercepts(host)` just to
compute the marker (derive it from `transforms_for` instead). sigv4's
targeted refusal diagnostics (`schemes.py:522-543`) are the model to extend.

**No credential-use audit trail** (filed as #24).

**`/health` liveness vs readiness** (filed as #23): `/health` 200s before the
mitmproxy CA exists while `/ca.crt` 503s (`bootstrap.py:160-168`), and the
CLI gates `start` on `/health` (`proxy_http.py:70-86`).

**IPv6/H3 drops are silent and host-dependent.** `entrypoint.sh:34` drops
UDP:443, `:38-40` drops IPv6 — invisible to the Python layer, so a workspace
tool that is IPv6-only or QUIC-pinned sees generic hangs. The IPv6 drop is
also best-effort: on a host without ip6tables it may silently *not* apply — a
behavior difference across hosts worth documenting (#25 covers the
workspace-facing doc; `docs/security.md` per #21 covers the guarantee-level
statement).

**Script authoring diagnostics** (filed as #26). Compile-time is good
(`config.py:282-290` surfaces the full compile error; `injector check
--compile` gives a true in-image verdict); request-time is type-name-only by
design, with no dev-mode escape hatch. Also: if the installed `starlark-pyo3`
lacks cancellation support, a runaway script wedges the whole proxy —
surfaced only in a module docstring today; warn at load time.

**Admin API is in good shape.** 401/503 distinction on auth
(`admin.py:115-122`), auth before body parsing (schema not fingerprintable
unauthenticated), config fingerprint fast-path degrading safely
(`admin.py:160-177`). No changes suggested.

**Minor:** the request-phase scheme-exception log prints `e` verbatim
(`addon.py:68`) — fine for current built-ins, but worth a comment (or
type-only formatting) so a future built-in incorporating secret material into
an exception message doesn't hit stdout.

### 4. Workspace-side / agent experience

**`/llms.txt` content gaps** (filed as #25): non-substitute schemes
unexplained (an agent seeing a `sigv4` binding with `placeholder: null` has
nothing actionable — the "configure dummy static creds" advice lives in a
proxy log the workspace can't read); IPv6/H3 drops unmentioned; `intercept_hosts`
returns glob *patterns* an agent may literal-match; the sign-family carrier
header is deliberately unpublished (`docs/injectors.md:494-502`) — a real gap
between the "agent self-configures from `/setup`" promise and reality, which
should at least be stated. Note #12 (sigv4 placeholder = dummy AKID) would
dissolve the sigv4 half of this.

**What's already good:** the `index` route's friendly route map instead of a
404 (`bootstrap.py:196-213`); `proxy.local` documented in three places with
the `169.254.1.1` fallback; the CA-only fallback for minimal images with an
explicit warning (`bootstrap.py:57-62`); `/setup`'s least-disclosure field
set.

**Missing human-side doc for the agent flow.** The headline use case is
LLM-agent sandboxes, but no doc tells the *operator* how the pieces are meant
to compose: `CREDPROXY_SETUP` pointing the agent at `/llms.txt`, the agent
reading `/setup`, what to put in an agent's system prompt. A short
`docs/agents.md` (or a `workspace.md` section) showing the intended bootstrap
loop would close it. (Folded into #20/#25 scope decisions; not separately
filed.)

### 5. Registries: injectors, providers, presets, scripts

**Scripted-injector tooling is undocumented where users look.** `injector
scaffold NAME --script [sign|substitute]` (emits a manifest *and* a `.star`
with the primitive API inline, `scaffold.py:245-288`), `injector api`, and
`injector check [--compile]` (`cli.py:1691-1844`) exist precisely because the
feature was "undiscoverable and un-authorable" — and `docs/injectors.md`'s
authoring sections (lines 188-264) hand-write both files and never mention
them. CLAUDE.md's command list is stale on the same points (also missing
`provider show`, `preset list`). Pure doc work with high leverage.

**Provider scaffold seeds from the weakest example.** `provider scaffold`
copies the `env` provider (`scaffold.py:24,130`), which is the one builtin
*lacking* the two-exit-code pattern every backend-wrapping provider needs
(`NotFound` → exit 2 vs backend-CLI-missing → exit 1; compare
`builtin/providers/op:62-73` with `env:53-60`). Meanwhile every provider's
footer comment claims it is "identical for every provider", which is false
for `env`. Seed the scaffold from a backend-shaped provider or add a
commented `Missing`-class stub to the env template; fix the comment.

**Provider failures under `--json`/CI lose their cause.** Provider stderr is
deliberately not captured (interactivity — documented in
`docs/providers.md:96-102`), so on a generic nonzero exit the structured
output carries only `provider 'X' failed (exit N)`. A last-line-of-stderr
capture (while still tee-ing to the terminal) would improve the
non-interactive story without breaking prompts.

**`oauth-reseal` vs `oauth2-reseal` is a naming trap.** Two builtin
injectors, one character apart — one the native scheme, one the Starlark
worked example — with nothing in `injector list` distinguishing them. Same
for the benchmark scripts `bearer.star`/`basic.star`/`body.star`, which
appear in `script list` looking like duplicates of the native schemes. A
naming convention (`example-` prefix) or a list-visible descriptor would fix
both.

**Preset registry lacks parity.** No `preset scaffold` (injectors and
providers both have one; orgs are told to author presets by hand-copying
`github.toml`), no source tier in `preset list` (`describe_presets`,
`presets.py:139-157` — every other registry's list shows its tier, so
"did my overlay shadow the builtin?" is unanswerable for presets alone), and
no `preset show` to mirror `provider show`.

**Shadowing is visible in aggregate but not per-name.** `info` gives per-tier
counts and a `profile_overrides` rollup, and each `list` shows the winner's
tier — but nothing shows that a specific builtin was *shadowed* by a
same-named user file. A shadow indicator in `list` would complete the
three-tier story.

**Stale source-label comments.** `Injector.source` and `Provider.source` are
commented `# "user" or "builtin"` (`injectors.py:86`, `providers.py:95`) but
the model is three-tier (`user`/`profile`/`builtin`). Cosmetic, but the tier
model is load-bearing.

### 6. Documentation & onboarding

**README** (filed as #20): no requirements/install, singular-container mental
model, quickstart step 5 duplicates the template's `setup`, step 3's
host-side `GITHUB_TOKEN` prerequisite unstated, Further reading missing
`forking.md` and pointing end users at CLAUDE.md unlabeled.

**No `docs/` index.** `docs/` has no README/TOC, and the docs serve three
distinct audiences without saying so. A `docs/README.md` labeling each doc's
audience (end user: `configuration.md`, `workspace.md`; authors:
`injectors.md`, `providers.md`; org forkers: `forking.md`,
`profile/README.md`; contributors: `CLAUDE.md`) is cheap and orienting.

**`configuration.md` front-loads deep material.** The 90-line non-root
uid/mount-ownership treatise (lines 204-295) sits between basic config and
the Bindings section a first-timer needs. Split it into its own doc or an
appendix so the linear read stays beginner-appropriate.

**Security doc** (filed as #21) and **troubleshooting guide** (filed as #22).

**Small accuracy notes:** `docs/injectors.md:492` says "fully backward
compatible", contradicting the project's explicit no-compat pre-release
stance (reword to "the prior behavior is the default"); CLAUDE.md
under-describes `dev test` (no mention of the `--cli`/`--proxy` split); the
CLI module docstring grammar (`cli.py:15-24`) omits `info`, `current`,
`config`, `edit`, `bind-dir`, `mount`, `preset`.

**No FAQ.** Natural questions ("does my image need modifying?" — no; "can I
run multiple workspaces?" — yes; "which runtimes?" — Docker Desktop /
rootful Docker / rootless podman, *not* rootless Docker per
`configuration.md:238-239`) are scattered; a short FAQ would surface them.

---

## Long-tail checklist

Not filed as issues; fine to pick up with adjacent work. Ordered roughly by
value.

- [ ] Empty `list`/`binding list` next-step hints (`render.py:60,311`)
- [ ] `workspace NAME --help` prints the verb menu (`cli.py:1376`)
- [ ] Slot-mismatch error teaches `--secret SLOT=REF`; unknown-slot detection (`bindings.py:243-248`, `cli.py:548-551`)
- [ ] Document `injector scaffold --script` / `api` / `check` in `docs/injectors.md`; refresh CLAUDE.md command list
- [ ] Provider scaffold: backend-shaped template + fix the "identical footer" comment
- [ ] Fix `config.py` module docstring (image/home/mounts schema drift)
- [ ] `mount list` / `mount remove` for symmetry with `binding`
- [ ] Rename or annotate `oauth-reseal` vs `oauth2-reseal`; `example-` prefix for the benchmark scripts
- [ ] `preset scaffold`, source tier in `preset list`, `preset show`
- [ ] Stable exit codes (or document `--json` `type` as the contract)
- [ ] `docs/README.md` index with audience labels; split the uid/ownership deep-dive out of `configuration.md`
- [ ] `docs/agents.md`: the operator-side agent bootstrap flow (`CREDPROXY_SETUP`, `/llms.txt`, `/setup`)
- [ ] Surface-aware next-step hints (`credp ...` vs `credproxy workspace ...`)
- [ ] Last-line-of-stderr capture on generic provider failure (non-interactive story)
- [ ] Shell completion generator
- [ ] Shadow indicator in registry `list`s; fix stale `source` comments
- [ ] Template: single-brace warning near `{{ }}` examples; add a preset-form binding example
- [ ] `docs/injectors.md:492` "fully backward compatible" wording; CLI docstring grammar refresh
- [ ] Comment (or type-only-format) the request-phase scheme-exception log (`addon.py:68`)
- [ ] Marker derivation from `transforms_for` instead of a second `intercepts()` call (`addon.py:84`)
- [ ] FAQ

## Method note

The review was conducted against commit `f19022c` by four parallel deep-read
passes (CLI surface; docs/onboarding; proxy runtime behavior; config
authoring & registries), then synthesized and spot-verified. One pre-existing
test failure was observed on a clean checkout in the review environment
(`tests/cli/test_providers.py::test_sh_provider_ref_with_space_not_split`) —
unrelated to any finding here, but worth a look.
