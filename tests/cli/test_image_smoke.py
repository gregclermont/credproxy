"""Smoke test: the BAKED proxy image must contain every runtime module.

`dev test` bind-mounts proxy/ over /opt/proxy, so the in-container suite never
exercises the image's own COPY'd layers -- a module left out of the Dockerfile
(the schemes.py/hostmatch.py/placeholders.py gap that motivated this) boots fine
under the tests yet crashes a real `docker run`. This boots the image with NO
source mount and imports every proxy/*.py module, so a missing/broken module
fails here. Skipped when docker or the built image is absent (so docker-less CI
and a fresh checkout stay green; `credproxy dev build` makes it run).
"""
import shutil
import subprocess

import pytest

from credproxy_cli.core.paths import IMAGE_TAG, PROXY_DIR


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "image", "inspect", IMAGE_TAG],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
    except OSError:
        return False


@pytest.mark.skipif(not _image_present(),
                    reason=f"{IMAGE_TAG} not built (run `credproxy dev build`)")
def test_baked_image_imports_every_proxy_module():
    mods = sorted(p.stem for p in PROXY_DIR.glob("*.py"))
    # Sanity: the glob actually found the runtime modules (incl. the ones the
    # Dockerfile used to omit), so an empty match can't make this pass vacuously.
    assert {"main", "schemes", "hostmatch", "placeholders"} <= set(mods)
    stmt = "import " + ", ".join(mods) + "\nprint('ok')"
    # NO `-v proxy/:/opt/proxy`: exercise the image's own baked layers.
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python", IMAGE_TAG, "-c", stmt],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"baked image failed to import proxy modules:\n{r.stderr}"
    assert "ok" in r.stdout
