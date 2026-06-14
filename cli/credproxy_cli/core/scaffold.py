"""Scaffold a user injector/provider from a bundled template.

Bundled definitions double as starting points: `scaffold` copies one into the
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
    bundled_injectors_dir,
    bundled_providers_dir,
    injectors_config_dir,
    providers_config_dir,
    scripts_config_dir,
)

# Which bundled definition seeds each kind of scaffold.
_INJECTOR_TEMPLATE = "bearer"  # generic bearer injector
_PROVIDER_TEMPLATE = "env"     # env-var provider script


@dataclass(frozen=True)
class ScaffoldResult:
    kind: str   # "injector" | "provider"
    name: str
    path: Path


def scaffold(kind: str, name: str) -> ScaffoldResult:
    """Copy the bundled template for `kind` into the user registry as `name`.

    Refuses to overwrite an existing file. Returns the destination path."""
    # A name is a single registry filename, never a flag or a path. Guards the
    # dispatcher's positional handling so e.g. `scaffold --help` can't write a
    # file named '--help'.
    if not name or name.startswith("-") or "/" in name or name in (".", ".."):
        raise CredproxyError(f"invalid {kind} name {name!r}")
    if kind == "injector":
        src = bundled_injectors_dir() / f"{_INJECTOR_TEMPLATE}.toml"
        dst_dir = injectors_config_dir()
        dst = dst_dir / f"{name}.toml"
    elif kind == "provider":
        src = bundled_providers_dir() / _PROVIDER_TEMPLATE
        dst_dir = providers_config_dir()
        dst = dst_dir / name
    else:
        raise CredproxyError(f"unknown scaffold kind {kind!r}")

    if dst.exists():
        raise CredproxyError(f"{dst} already exists; refusing to overwrite")
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    if kind == "provider":
        # Preserve the executable bit so the copy is directly runnable.
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
