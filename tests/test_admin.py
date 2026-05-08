"""Tests for proxy/admin.py — bearer-auth + /admin/health + /admin/config."""
import json

import pytest

import admin


@pytest.fixture
def config_file(tmp_path):
    """Path the /admin/config endpoint will write to."""
    return tmp_path / "config.json"


@pytest.fixture
def reload_calls():
    """Sentinel list — appended whenever the admin reload_fn is called."""
    return []


@pytest.fixture
def app(config_file, reload_calls):
    return admin.make_admin_app(
        auth_token="secret-token-abc",
        config_path=config_file,
        reload_fn=lambda: reload_calls.append(True),
    )


VALID_CONFIG = {
    "hosts": {
        "api.github.com": {
            "headers": {
                "Authorization": {
                    "placeholder": "credproxy_test",
                    "real": "github_pat_real",
                }
            }
        }
    }
}


# ---- /admin/health: auth middleware ----

async def test_health_with_correct_token(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/health",
        headers={"Authorization": "Bearer secret-token-abc"},
    )
    assert resp.status == 200
    assert await resp.json() == {"ok": True}


async def test_health_no_authorization_header(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/admin/health")
    assert resp.status == 401


async def test_health_wrong_scheme(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/health",
        headers={"Authorization": "Basic c2VjcmV0LXRva2VuLWFiYw=="},
    )
    assert resp.status == 401


async def test_health_wrong_token(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/health",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status == 401


async def test_health_close_match_token(aiohttp_client, app):
    """Off-by-one-character token must still 401 (no prefix-match leak)."""
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/health",
        headers={"Authorization": "Bearer secret-token-ab"},
    )
    assert resp.status == 401


# ---- /admin/config ----

async def test_set_config_writes_file_and_reloads(
    aiohttp_client, app, config_file, reload_calls
):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer secret-token-abc"},
        json=VALID_CONFIG,
    )
    assert resp.status == 200
    assert await resp.json() == {"ok": True, "reloading": True}

    on_disk = json.loads(config_file.read_text())
    assert on_disk == VALID_CONFIG
    assert reload_calls == [True]


async def test_set_config_requires_auth(aiohttp_client, app, config_file, reload_calls):
    client = await aiohttp_client(app)
    resp = await client.post("/admin/config", json=VALID_CONFIG)
    assert resp.status == 401
    assert not config_file.exists()
    assert reload_calls == []


async def test_set_config_rejects_unresolved_secret_reference(
    aiohttp_client, app, config_file, reload_calls
):
    """The endpoint refuses ${secret:NAME} -- caller must resolve client-side."""
    bad = {
        "hosts": {
            "api.github.com": {
                "headers": {
                    "Authorization": {
                        "placeholder": "ph",
                        "real": "${secret:GITHUB_PAT}",
                    }
                }
            }
        }
    }
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer secret-token-abc"},
        json=bad,
    )
    assert resp.status == 400
    body = await resp.json()
    assert "GITHUB_PAT" in body["error"]
    assert not config_file.exists()
    assert reload_calls == []


async def test_set_config_rejects_invalid_schema(
    aiohttp_client, app, config_file, reload_calls
):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"not-hosts": {}},
    )
    assert resp.status == 400
    assert not config_file.exists()
    assert reload_calls == []


async def test_set_config_malformed_json(aiohttp_client, app, config_file):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={
            "Authorization": "Bearer secret-token-abc",
            "Content-Type": "application/json",
        },
        data=b"not json",
    )
    assert resp.status == 400
    assert not config_file.exists()


async def test_set_config_overwrites_existing_file(
    aiohttp_client, app, config_file
):
    config_file.write_text(json.dumps({"hosts": {"old.example.com": {}}}))
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer secret-token-abc"},
        json=VALID_CONFIG,
    )
    assert resp.status == 200
    assert json.loads(config_file.read_text()) == VALID_CONFIG
