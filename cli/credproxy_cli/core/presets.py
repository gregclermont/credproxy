"""Presets: CLI-side generators that emit a coordinated set of bindings.

A preset packages the multi-binding shape a single credential needs across a
service's hosts and schemes -- e.g. a GitHub PAT is `bearer` on api.github.com
but HTTP `basic` on github.com / ghcr.io. The generated bindings share ONE
bare-token placeholder, so there is no hand-computed base64 and no fragile
cross-binding coupling (design-v3, #3). A preset is pure host-side config
generation: it produces ordinary `[[binding]]` blocks; the proxy never sees a
"preset". Editing or removing the generated bindings afterwards is normal.
"""
from __future__ import annotations

from dataclasses import dataclass

from .bindings import Binding
from .errors import CredproxyError
from .injectors import Placeholder


@dataclass(frozen=True)
class _Part:
    suffix: str             # appended to the preset's base name
    injector: str           # bundled injector / scheme to use
    hosts: tuple[str, ...]
    env: str | None


@dataclass(frozen=True)
class PresetSpec:
    name: str
    placeholder: Placeholder  # the shared, service-shaped sentinel
    parts: tuple[_Part, ...]


PRESETS: dict[str, PresetSpec] = {
    # A classic-PAT-shaped placeholder (ghp_ + 36 alnum = 40) shared across all
    # three bindings, so client-side token-format checks still pass.
    "github": PresetSpec(
        name="github",
        placeholder=Placeholder("ghp_", 40, "alnumeric"),
        parts=(
            _Part("api", "bearer", ("api.github.com",), "GITHUB_TOKEN"),
            _Part("git", "basic", ("github.com",), None),
            _Part("ghcr", "basic", ("ghcr.io",), None),
        ),
    ),
}


def build_preset(preset: str, provider: str, secret: str) -> list[Binding]:
    """Generate the binding set for `preset`, all sharing one freshly-generated
    placeholder and resolving the same single-slot `secret` ref via `provider`.
    Raises CredproxyError on an unknown preset name."""
    spec = PRESETS.get(preset)
    if spec is None:
        raise CredproxyError(
            f"unknown preset {preset!r}; known presets: {', '.join(sorted(PRESETS))}"
        )
    placeholder = spec.placeholder.generate()
    return [
        Binding(
            name=f"{spec.name}-{part.suffix}",
            injector=part.injector,
            provider=provider,
            secret=secret,
            hosts=part.hosts,
            placeholder=placeholder,
            env=part.env,
        )
        for part in spec.parts
    ]
