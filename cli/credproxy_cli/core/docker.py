"""Thin wrappers over the `docker` CLI.

These do not print; on failure they raise DockerError. `stream=True`
sends docker's output straight to the terminal (used by `dev build`),
which is the one place docker output is allowed to reach the user
directly -- porcelain owns that decision by passing the flag through.
"""
from __future__ import annotations

import subprocess

from .errors import DockerError


def docker(args: list[str], stream: bool = False) -> None:
    """Run `docker <args>`; raise DockerError on error. With stream=True,
    docker's output goes straight to the terminal."""
    if stream:
        if subprocess.run(["docker", *args], check=False).returncode != 0:
            raise DockerError(f"docker {args[0]} failed")
        return
    r = subprocess.run(
        ["docker", *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        raise DockerError(f"docker {args[0]} failed: {r.stderr.strip()}")


def docker_quiet(args: list[str]) -> None:
    """Run `docker <args>`, ignoring failures (best-effort cleanup)."""
    subprocess.run(
        ["docker", *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def docker_output(args: list[str]) -> str:
    """Run `docker <args>` and return stdout; raise DockerError on error."""
    r = subprocess.run(
        ["docker", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        raise DockerError(f"docker {args[0]} failed: {r.stderr.strip()}")
    return r.stdout


def inspect(ref: str, fmt: str) -> str | None:
    """`docker inspect -f <fmt> <ref>`; None if the object is absent."""
    r = subprocess.run(
        ["docker", "inspect", "-f", fmt, ref],
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def container_status(name: str) -> str | None:
    """running / exited / created / ... ; None if the container is absent."""
    return inspect(name, "{{.State.Status}}")


def running_workspaces() -> list[str]:
    """Names of workspaces with a running credproxy container."""
    r = subprocess.run(
        ["docker", "ps", "--filter", "label=credproxy.role",
         "--format", '{{.Label "credproxy.workspace"}}'],
        capture_output=True,
        text=True,
        check=False,
    )
    return sorted({line for line in r.stdout.split() if line})


def resolve_host_port(container_name: str, container_port: int) -> int:
    """Return the host port Docker mapped to *container_port* for *container_name*.

    Uses `docker port <container> <port>/tcp`, which is self-healing: it
    queries Docker's live NetworkSettings each time, so a container restart
    (which may reassign an ephemeral port) is always reflected correctly.

    Raises DockerError if the container is not running or the port is not
    published."""
    r = subprocess.run(
        ["docker", "port", container_name, f"{container_port}/tcp"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0 or not r.stdout.strip():
        raise DockerError(
            f"cannot resolve host port for {container_name}:{container_port}/tcp"
            f" — is the container running? ({r.stderr.strip()})"
        )
    # Output is one or more lines like "127.0.0.1:54321"; take the first
    # 127.0.0.1 binding.
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("127.0.0.1:"):
            _, port_str = line.rsplit(":", 1)
            return int(port_str)
    # Fallback: parse the first line regardless of address
    first = r.stdout.splitlines()[0].strip()
    _, port_str = first.rsplit(":", 1)
    return int(port_str)
