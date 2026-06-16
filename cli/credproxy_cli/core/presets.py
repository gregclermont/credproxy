"""Presets: CLI-side generators that emit a coordinated set of bindings.

A preset packages the multi-binding shape a single credential needs across a
service's hosts and schemes -- e.g. a GitHub PAT is `bearer` on api.github.com
but HTTP `basic` on github.com / ghcr.io. The generated bindings share ONE
bare-token placeholder, so there is no hand-computed base64 and no fragile
cross-binding coupling. A preset is pure host-side config
generation: it produces ordinary `[[binding]]` blocks; the proxy never sees a
"preset". Editing or removing the generated bindings afterwards is normal.

Presets are *data*, loaded from the layered registry (user > profile overlay >
builtin, paths.layered_dirs) -- a `<name>.toml` per preset, the name being the
filename stem. So an org adds its own coordinated sets (an internal artifact
registry, say) by dropping a TOML in its profile overlay, no code. See
docs/forking.md and builtin/presets/github.toml for the shape.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass

from .bindings import Binding
from .errors import ConfigError, CredproxyError
from .injectors import Placeholder
from .paths import layered_dirs


@dataclass(frozen=True)
class _Part:
    suffix: str             # appended to the preset's base name
    injector: str           # injector / scheme to use
    hosts: tuple[str, ...]
    env: str | None


@dataclass(frozen=True)
class PresetSpec:
    name: str
    placeholder: Placeholder  # the shared, service-shaped sentinel
    parts: tuple[_Part, ...]
    # A canonical source so the common case needs no flags. `default_provider`
    # fills an omitted `--provider`. `default_secret` fills an omitted `--secret`
    # but ONLY when the resolved provider is `default_provider` -- a secret ref's
    # meaning is provider-specific (a gh hostname is not an env-var name nor an
    # op:// path), so it can't be defaulted for an arbitrary provider.
    default_provider: str | None = None
    default_secret: str | None = None


def _parse_preset(path, name: str) -> PresetSpec:
    src = f"preset '{name}' ({path})"
    try:
        raw = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{src}: unreadable ({e})")

    ph = raw.get("placeholder")
    if not isinstance(ph, dict):
        raise ConfigError(f"{src}: missing [placeholder] table")
    try:
        placeholder = Placeholder(
            prefix=ph["prefix"], length=ph["length"], charset=ph["charset"])
    except KeyError as e:
        raise ConfigError(f"{src}: [placeholder] missing {e}")

    parts_raw = raw.get("part")
    if not isinstance(parts_raw, list) or not parts_raw:
        raise ConfigError(f"{src}: needs a non-empty [[part]] array")
    parts = []
    for i, pr in enumerate(parts_raw):
        where = f"{src} part[{i}]"
        if not isinstance(pr, dict):
            raise ConfigError(f"{where}: must be a table")
        suffix, injector = pr.get("suffix"), pr.get("injector")
        hosts = pr.get("hosts")
        if not isinstance(suffix, str) or not suffix:
            raise ConfigError(f"{where}: 'suffix' must be a non-empty string")
        if not isinstance(injector, str) or not injector:
            raise ConfigError(f"{where}: 'injector' must be a non-empty string")
        if not isinstance(hosts, list) or not hosts \
                or not all(isinstance(h, str) and h for h in hosts):
            raise ConfigError(f"{where}: 'hosts' must be a non-empty array of strings")
        env = pr.get("env")
        if env is not None and (not isinstance(env, str) or not env):
            raise ConfigError(f"{where}: 'env' must be a non-empty string or absent")
        parts.append(_Part(suffix=suffix, injector=injector,
                           hosts=tuple(hosts), env=env))

    return PresetSpec(
        name=name,
        placeholder=placeholder,
        parts=tuple(parts),
        default_provider=raw.get("default_provider"),
        default_secret=raw.get("default_secret"),
    )


def load_presets() -> dict[str, PresetSpec]:
    """All resolvable presets keyed by name, user shadowing profile shadowing
    builtin (least-specific first so the most-specific overwrites)."""
    seen: dict[str, PresetSpec] = {}
    for _source, base in reversed(layered_dirs("presets")):
        if not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            if path.suffix == ".toml" and path.is_file():
                seen[path.stem] = _parse_preset(path, path.stem)
    return seen


def get_preset(name: str) -> PresetSpec:
    presets = load_presets()
    spec = presets.get(name)
    if spec is None:
        raise CredproxyError(
            f"unknown preset {name!r}; known presets: "
            f"{', '.join(sorted(presets)) or '(none)'}"
        )
    return spec


def describe_presets() -> list[dict]:
    """Structured description of every known preset, for `preset list`: each
    preset's name and the bindings it expands to (suffix/injector/hosts/env).
    No secret/provider -- those are supplied at `binding add` time."""
    return [
        {
            "name": spec.name,
            "bindings": [
                {
                    "name": f"{spec.name}-{part.suffix}",
                    "injector": part.injector,
                    "hosts": list(part.hosts),
                    "env": part.env,
                }
                for part in spec.parts
            ],
        }
        for spec in sorted(load_presets().values(), key=lambda s: s.name)
    ]


def build_preset(preset: str, provider: str, secret: str) -> list[Binding]:
    """Generate the binding set for `preset`, all sharing one freshly-generated
    placeholder and resolving the same single-slot `secret` ref via `provider`.
    Raises CredproxyError on an unknown preset name."""
    spec = get_preset(preset)
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
