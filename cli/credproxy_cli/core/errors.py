"""Typed exceptions raised by the core.

The core never calls sys.exit; it raises these. Porcelain catches
CredproxyError and renders it via _fail (exit 1 with the `[credproxy] `
prefix). Subclasses exist so later waves (and `--json` rendering) can
distinguish failure kinds without string-matching; today porcelain
treats them uniformly.
"""
from __future__ import annotations


class CredproxyError(Exception):
    """Base for all core-raised, user-facing errors. `str(e)` is the
    message porcelain renders."""


class ConfigError(CredproxyError):
    """A problem with a workspace's config TOML (missing, malformed, or
    failing validation), or a missing host-env secret referenced by it."""


class WorkspaceError(CredproxyError):
    """A workspace is missing, already exists, or has an invalid name."""


class ImageError(CredproxyError):
    """The proxy image is missing or does not declare the env contract."""


class DockerError(CredproxyError):
    """A `docker` invocation failed."""


class ProxyError(CredproxyError):
    """The proxy did not become ready, rejected the token, or returned an
    error from /admin/config."""


class DependencyError(CredproxyError):
    """A host-side dependency is missing."""


class ProviderError(CredproxyError):
    """A provider could not be found, failed to execute, returned a
    malformed response, or reported that the secret does not exist. The
    message names the provider, the secret id, and a tail of the
    provider's stderr where available."""


class InjectorError(CredproxyError):
    """An injector definition could not be found or is malformed
    (missing/invalid `header`, bad `[placeholder]` charset, etc.)."""
