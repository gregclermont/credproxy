"""Scaffold a user injector/provider from a builtin template.

Builtin definitions double as starting points: `scaffold` copies one into the
user registry under a new name so you can author from it. Filesystem-native --
the copied file IS the registry entry, referenced by name.
"""
from __future__ import annotations

import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import CredproxyError
from .paths import (
    builtin_injectors_dir,
    builtin_providers_dir,
    injectors_config_dir,
    providers_config_dir,
    scripts_config_dir,
)

# Which builtin definition seeds each kind of scaffold.
_INJECTOR_TEMPLATE = "bearer"  # generic bearer injector
_PROVIDER_TEMPLATE = "env"     # env-var provider script (the python default)

PROVIDER_LANGS = ("python", "sh")

# Second-language provider template: the env provider in POSIX sh + jq. Same
# protocol and three-zone shape as the python default, so the two diff cleanly
# (only fetch() and the dispatch syntax differ). Kept here, NOT under
# builtin/providers/, so it doesn't show up as a real provider in `list`.
_PROVIDER_TEMPLATE_SH = '''#!/bin/sh
# credproxy provider: env  —  protocol: docs/providers.md  (needs jq)
#
# A provider is any executable speaking the batch protocol. This is the env
# provider written in POSIX sh + jq, as a starting point: edit the metadata and
# fetch() for your backend. Copy with `credproxy provider scaffold NAME --lang sh`.
set -u

# ════ metadata ════════════════════════════════════════════════════════
NAME="env"
DESCRIPTION="Host environment variables"
PROTOCOL_VERSION=1
HELP='Reads host environment variables.
  ref:     the environment variable NAME (e.g. GITHUB_TOKEN)
  example: --provider env --secret GITHUB_TOKEN
The variable must be set in the shell that runs credproxy.'

# ════ fetch one secret (the only provider-specific logic) ═════════════
# Print the secret for "$1" on stdout and return 0; return non-zero if the ref
# does not resolve. Swap in your backend, e.g.  op read "$1"  /  vault kv get …
fetch() {
  printenv "$1"
}

# ════ protocol footer (identical for every sh provider — needs jq) ════
req=$(cat)
printf '%s' "$req" | jq -e . >/dev/null 2>&1 || {
  echo "$NAME provider: bad request JSON" >&2; exit 1; }
[ "$(printf '%s' "$req" | jq -r '.version')" = "$PROTOCOL_VERSION" ] || {
  echo "$NAME provider: unsupported version" >&2; exit 3; }
op=$(printf '%s' "$req" | jq -r '.op')
case "$op" in
  describe) jq -n --arg d "$DESCRIPTION" '{description: $d}' ;;
  help)     jq -n --arg h "$HELP"        '{help: $h}' ;;
  get)
    # Stream refs NEWLINE-delimited into the loop. Do NOT use
    # `for ref in $(...)`: unquoted command substitution word-splits a ref that
    # contains spaces (common for `op`/`bw`/keychain item names) and pathname-
    # expands a `*` in it. `IFS= read -r` keeps each ref whole and literal.
    # The loop runs in the pipe's subshell, so it accumulates AND emits there;
    # `|| exit $?` propagates a fetch failure out of the subshell.
    printf '%s' "$req" | jq -r '(.secrets // [])[]' | {
      values='{}'
      while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        val=$(fetch "$ref") || { echo "$NAME provider: '$ref' not found" >&2; exit 2; }
        values=$(printf '%s' "$values" | jq --arg k "$ref" --arg v "$val" '.[$k] = $v')
      done
      printf '%s' "$values" | jq -c '{values: .}'
    } || exit $?
    ;;
  *) echo "$NAME provider: unsupported op" >&2; exit 3 ;;
esac
'''


@dataclass(frozen=True)
class ScaffoldResult:
    kind: str   # "injector" | "provider"
    name: str
    path: Path


def scaffold(kind: str, name: str, lang: str = "python") -> ScaffoldResult:
    """Seed a `kind` definition into the user registry as `name`. Providers can
    pick a template language (`python` default, or `sh` for POSIX shell + jq).

    Refuses to overwrite an existing file. Returns the destination path."""
    # A name is a single registry filename, never a flag or a path. Guards the
    # dispatcher's positional handling so e.g. `scaffold --help` can't write a
    # file named '--help'.
    if not name or name.startswith("-") or "/" in name or name in (".", ".."):
        raise CredproxyError(f"invalid {kind} name {name!r}")
    if kind == "injector":
        if lang != "python":
            raise CredproxyError("--lang is only valid for `provider scaffold`")
        src = builtin_injectors_dir() / f"{_INJECTOR_TEMPLATE}.toml"
        dst = injectors_config_dir() / f"{name}.toml"
        if dst.exists():
            raise CredproxyError(f"{dst} already exists; refusing to overwrite")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        return ScaffoldResult(kind="injector", name=name, path=dst)

    if kind != "provider":
        raise CredproxyError(f"unknown scaffold kind {kind!r}")
    if lang not in PROVIDER_LANGS:
        raise CredproxyError(
            f"unknown --lang {lang!r}; choose {' or '.join(PROVIDER_LANGS)}"
        )
    dst = providers_config_dir() / name
    if dst.exists():
        raise CredproxyError(f"{dst} already exists; refusing to overwrite")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if lang == "sh":
        dst.write_text(_PROVIDER_TEMPLATE_SH)
    else:
        shutil.copyfile(builtin_providers_dir() / _PROVIDER_TEMPLATE, dst)
    # Preserve/set the executable bit so the provider is directly runnable.
    dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return ScaffoldResult(kind=kind, name=name, path=dst)


# ---- scripted-injector scaffold ---------------------------------------------
#
# The escape hatch: scheme="script" runs a sandboxed Starlark `.star` the proxy
# compiles per request. Blind-usability rounds showed it was undiscoverable and
# un-authorable from the CLI (scaffold only emitted the bearer template, and the
# primitive API was nowhere). This emits a working manifest + a `.star` that
# carries the full primitive-API reference inline, so authoring is copy-and-edit.

_VALID_FAMILIES = ("sign", "substitute")

# Shared API reference, prepended to every scaffolded script.
_STAR_API_REF = """\
# Define on_request() (and optionally on_response()); both take NO arguments --
# the request/response context is implicit. Mutate the request via req_set_*;
# the return value is ignored. Read declared secret slots with secret("<slot>").
#
# Primitive API (api 1) -- implicit context, no imports, no load():
#   secret(slot="value")          resolved secret for a slot
#   param(key, default=None)      a manifest [params] value
#   placeholder()                 the inert placeholder (substitute family)
#   req_method() req_host() req_path() req_header(name) req_body() req_body_b64()
#   req_set_header(name, value)   set/overwrite a request header
#   req_set_body(text)            replace the request body
#   resp_status() resp_header(name) resp_body() resp_json()
#   resp_set_header(name, value)  resp_set_body(text)
#   mint(value, ttl)  mint_into_json(field, value, ttl)        (re-seal)
#   hmac_sha256(key_b64, msg)     HMAC-SHA256, base64 key -> base64
#   hmac_sha256_hex(key, msg)     HMAC-SHA256 -> hex
#   sha256_hex(s) sha1_hex(s)
#   b64encode/b64decode/b64url_encode/b64url_decode/b64_to_hex/hex_to_b64
#   rs256_sign(pem, msg)  jwt_encode_sign(header, claims, pem)
#   json_encode(v) json_decode(s)  now() now_ms()
"""

_MANIFEST = {
    "sign": """\
# credproxy scripted injector: {name}  (custom injection logic in Starlark)
#
# Edit {name}.star (in the scripts dir) to implement the logic, then:
#   credproxy workspace NAME binding add --injector {name} --provider env \\
#       --secret key=YOUR_SECRET_ENV --host api.example.com
#   credproxy injector check {name}            # host-side checks
#   credproxy injector check {name} --compile  # compile in the proxy image

scheme        = "script"     # marks this as a scripted (custom) injector
script        = "{name}"     # the .star file resolved by this name
api           = 1            # primitive-API version the script targets
family        = "sign"       # compute auth material on every request
                            #   (use "substitute" to swap an inert placeholder)
slots         = ["key"]      # named secret inputs; bind each with --secret slot=REF
location_kind = "header"     # "header" or "body"
""",
    "substitute": """\
# credproxy scripted injector: {name}  (custom injection logic in Starlark)
#
# Edit {name}.star (in the scripts dir) to implement the logic, then:
#   credproxy workspace NAME binding add --injector {name} --provider env \\
#       --secret YOUR_SECRET_ENV --host api.example.com
#   credproxy injector check {name}            # host-side checks
#   credproxy injector check {name} --compile  # compile in the proxy image

scheme        = "script"     # marks this as a scripted (custom) injector
script        = "{name}"     # the .star file resolved by this name
api           = 1            # primitive-API version the script targets
family        = "substitute" # swap an inert placeholder for the real value
                            #   (use "sign" to compute auth material instead)
slots         = ["value"]    # the single secret; bind with --secret REF
location_kind = "header"     # "header" or "body"
""",
}

_STAR_EXAMPLE = {
    "sign": """\
# Example: sign each request with HMAC-SHA256 over method+path+body and write
# the hex signature into a custom header. `key` is the declared secret slot.

def on_request():
    msg = req_method() + "\\n" + req_path() + "\\n" + req_body()
    req_set_header("X-My-Signature", hmac_sha256_hex(secret("key"), msg))
""",
    "substitute": """\
# Example: replace the inert placeholder in the Authorization header with the
# real secret. The workspace only ever holds placeholder(); the swap is here.

def on_request():
    auth = req_header("Authorization")
    if auth:
        req_set_header("Authorization", auth.replace(placeholder(), secret("value")))
""",
}


_MANIFEST_REF = """\
Scripted injectors (scheme = "script") let you author custom injection logic.

Manifest fields (a TOML injector; generate with `injector scaffold NAME --script`):
  scheme        = "script"
  script        = "NAME"        # the .star file, resolved from the script registry
  api           = 1             # primitive-API version the script targets
  family        = "sign"        # sign: compute auth material every request (no
                                #   placeholder); substitute: swap an inert
                                #   placeholder the workspace holds for the value
  slots         = ["key"]       # named secret inputs; bind with --secret slot=REF
  location_kind = "header"      # "header" or "body"

Script (.star) contract and primitives:
"""


def script_api_reference() -> str:
    """The scripted-injector authoring reference (manifest fields + the Starlark
    primitive API). Shown by `injector api`; the same primitive list is embedded
    as comments in every scaffolded script, so there is one source of truth."""
    body = "\n".join(
        line[2:] if line.startswith("# ") else line[1:] if line.startswith("#") else line
        for line in _STAR_API_REF.splitlines()
    )
    return _MANIFEST_REF + body + "\n"


@dataclass(frozen=True)
class ScriptScaffoldResult:
    name: str
    injector_path: Path
    script_path: Path
    family: str


def scaffold_script(name: str, family: str = "sign") -> ScriptScaffoldResult:
    """Emit a scripted-injector pair: a manifest `<name>.toml` (scheme=script)
    in the injector registry, and a worked `<name>.star` (with the primitive-API
    reference inline) in the script registry. Refuses to overwrite either."""
    if not name or name.startswith("-") or "/" in name or name in (".", ".."):
        raise CredproxyError(f"invalid injector name {name!r}")
    if family not in _VALID_FAMILIES:
        raise CredproxyError(
            f"--script family must be one of {', '.join(_VALID_FAMILIES)} "
            f"(got {family!r})"
        )
    inj = injectors_config_dir() / f"{name}.toml"
    scr = scripts_config_dir() / f"{name}.star"
    for p in (inj, scr):
        if p.exists():
            raise CredproxyError(f"{p} already exists; refusing to overwrite")

    header = f"# credproxy scripted injector script: {name}.star  (api 1, family \"{family}\")\n#\n"
    star = header + _STAR_API_REF + "#\n" + _STAR_EXAMPLE[family]

    inj.parent.mkdir(parents=True, exist_ok=True)
    scr.parent.mkdir(parents=True, exist_ok=True)
    inj.write_text(_MANIFEST[family].replace("{name}", name))
    scr.write_text(star)
    return ScriptScaffoldResult(name=name, injector_path=inj, script_path=scr, family=family)
