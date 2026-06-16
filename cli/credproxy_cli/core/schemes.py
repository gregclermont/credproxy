"""Scheme catalog (CLI side).

The proxy implements injection schemes (`proxy/schemes.py`); the CLI needs to
*know about* them to validate injectors/bindings and to map secret slots onto
provider refs. The CLI cannot import proxy code (separate deploy unit), so this
is a small parallel catalog of the metadata the host side needs:

  - `family`        — "substitute" | "sign" (mirrors the proxy split)
  - `slots`         — secret slot names the scheme consumes
  - `param_defaults`— scheme params with their defaults (merged into the
                      injector's `[params]`)

Like RESERVED_NAMES, this duplicates knowledge that physically lives in
`proxy/schemes.py`; the two are kept in sync by hand (a divergence shows up as
a config the proxy rejects). Adding a scheme = one entry here + one in the
proxy registry.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .errors import InjectorError


@dataclass(frozen=True)
class SchemeSpec:
    name: str
    family: str               # "substitute" | "sign"
    slots: tuple[str, ...]
    param_defaults: dict = field(default_factory=dict)
    # Where on the wire the scheme writes (mirrors proxy/schemes). "header"
    # schemes write the header named by params["header"] (default
    # `header_default`); "body" schemes write the request body. Drives
    # collision detection without per-scheme name matching.
    location_kind: str = "header"
    header_default: str | None = "Authorization"

    @property
    def uses_placeholder(self) -> bool:
        """Substitute-family schemes hold an inert placeholder; sign schemes
        (sigv4, ...) compute auth material and have none."""
        return self.family == "substitute"


CATALOG: dict[str, SchemeSpec] = {
    "bearer": SchemeSpec("bearer", "substitute", ("value",),
                         {"header": "Authorization"}),
    "basic":  SchemeSpec("basic",  "substitute", ("value",),
                         {"header": "Authorization"}),
    "body":   SchemeSpec("body",   "substitute", ("value",), {},
                         location_kind="body", header_default=None),
    # Sign family: AWS SigV4. region/service are read from the request, so no
    # params; the workspace holds throwaway creds and the proxy re-signs. It
    # rewrites the Authorization header, so it collides there.
    "sigv4":  SchemeSpec("sigv4",  "sign", ("access_key_id", "secret_access_key"), {}),
    # Re-seal family: OAuth2 client-credentials. The binding is scoped to the
    # token endpoint; on_request swaps the client_secret placeholder in the body
    # (so it's "substitute"), on_response mints the returned token as a dynamic
    # placeholder on `api_hosts` (required param). token_field/expires_field/ttl/
    # reseal_header tune the response handling.
    "oauth2-reseal": SchemeSpec(
        "oauth2-reseal", "substitute", ("value",),
        {"token_field": "access_token", "expires_field": "expires_in",
         "ttl": "3600", "reseal_header": "Authorization"},
        location_kind="body", header_default=None),
}


_FAMILIES = ("substitute", "sign")
_LOCATION_KINDS = ("header", "body")


def get_scheme(name: str) -> SchemeSpec:
    spec = CATALOG.get(name)
    if spec is None:
        raise InjectorError(
            f"unknown scheme {name!r}; known schemes: "
            f"{', '.join(sorted(CATALOG))} -- or use scheme=\"script\" for a "
            f"custom injector (`credproxy injector scaffold NAME --script`)"
        )
    return spec


def build_script_spec(
    *,
    family: str,
    slots,
    location_kind: str = "header",
    header_default: str | None = "Authorization",
    where: str = "scripted injector",
) -> SchemeSpec:
    """Build (and validate) a SchemeSpec for a scripted injector (scheme =
    "script"), whose family/slots/location are declared in the TOML rather than
    coming from CATALOG. The spec name is fixed to "script" -- the wire
    dispatch key -- with the script source carried separately."""
    if family not in _FAMILIES:
        raise InjectorError(
            f"{where}: family must be one of {', '.join(_FAMILIES)} (got {family!r})"
        )
    if not isinstance(slots, (list, tuple)) or not slots \
            or not all(isinstance(s, str) and s for s in slots):
        raise InjectorError(
            f"{where}: slots must be a non-empty list of non-empty strings"
        )
    if location_kind not in _LOCATION_KINDS:
        raise InjectorError(
            f"{where}: location_kind must be one of "
            f"{', '.join(_LOCATION_KINDS)} (got {location_kind!r})"
        )
    if header_default is not None and not isinstance(header_default, str):
        raise InjectorError(f"{where}: header must be a string")
    return SchemeSpec(
        name="script", family=family, slots=tuple(slots), param_defaults={},
        location_kind=location_kind, header_default=header_default,
    )


def merge_params(spec: SchemeSpec, params: dict | None) -> dict:
    """Overlay the injector's `[params]` onto the scheme's defaults. Unknown
    keys are kept (schemes may accept open params),
    so this never rejects an extra key; it only fills defaults."""
    merged = dict(spec.param_defaults)
    if params:
        merged.update(params)
    return merged


def location_key(spec: SchemeSpec, params: dict) -> tuple:
    """A stable identifier for *where on the wire* this scheme writes, used to
    detect two bindings colliding on the same host. Data-driven (no per-scheme
    name matching): header schemes key on the resolved header name, others on
    their location_kind. Mirrors proxy/schemes.location_key."""
    if spec.location_kind == "header":
        return ("header", params.get("header", spec.header_default))
    return (spec.location_kind,)
