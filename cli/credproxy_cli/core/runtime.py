"""Container-runtime probing (cached).

credproxy shells `docker`, which may actually be podman (the `podman-docker`
shim provides a `docker` that execs podman). For the host-user uid-mapping
feature (`map_host_user`) we need to know one specific thing: is the runtime
**podman, rootless**? That is the only case where the workspace's non-root user
can't read/write bind mounts without `--userns=keep-id` -- on Docker the uid
matches 1:1 (or the share is permissive), so no userns lever is wanted.

The probe asks the *daemon*, so it is correct even when the binary is a shim,
via a podman-shaped `info` field that doubles as the engine discriminator:
podman's info has `.Host.Security.Rootless` (true/false); real Docker's info has
no `.Host`, so the Go template errors there. Error or non-podman -> we treat it
as "not podman-rootless" and inject nothing.
"""
from __future__ import annotations

import functools
import subprocess


@functools.lru_cache(maxsize=1)
def is_podman_rootless() -> bool:
    """True iff the active container runtime is podman running rootless.

    Cached for the process: the runtime doesn't change under a running CLI, and
    `docker info` is a daemon round-trip we don't want to repeat. Any failure
    (no binary, daemon down, real Docker's template error) yields False -- the
    safe default that injects no userns flag."""
    try:
        r = subprocess.run(
            ["docker", "info", "-f", "{{.Host.Security.Rootless}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # Real Docker: no `.Host` field -> non-zero exit. Podman: prints true/false.
    return r.returncode == 0 and r.stdout.strip() == "true"
