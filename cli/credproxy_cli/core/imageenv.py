"""The proxy image's self-declared API contract.

The proxy image declares its API via Dockerfile `ENV`. The CLI reads the
values via `docker inspect`'s `Config.Env` so the image is the single
source of truth for ports and mount-target paths.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from .errors import ImageError
from .paths import IMAGE_TAG


@dataclass(frozen=True)
class ImageEnv:
    http_port: int
    tmpfs: str
    token: str
    source: str

    @classmethod
    def load(cls, image: str | None = None) -> "ImageEnv":
        image = image or IMAGE_TAG
        try:
            out = subprocess.check_output(
                ["docker", "inspect", image], stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            raise ImageError(
                f"image {image} not found; run `credproxy dev build` first"
            )
        env_lines = json.loads(out)[0]["Config"].get("Env") or []
        env = dict(line.split("=", 1) for line in env_lines if "=" in line)
        try:
            return cls(
                http_port=int(env["CREDPROXY_HTTP_PORT"]),
                tmpfs=env["CREDPROXY_TMPFS"],
                token=env["CREDPROXY_TOKEN_PATH"],
                source=env["CREDPROXY_SOURCE"],
            )
        except KeyError as e:
            raise ImageError(
                f"image {image} is missing env var {e}; rebuild with "
                f"`credproxy dev build`"
            )
