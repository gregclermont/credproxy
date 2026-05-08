"""Tests for proxy/admin.py — bearer-auth + /admin/health + /admin/secrets."""
import json

import pytest

import admin


@pytest.fixture
def secrets_file(tmp_path):
    """Pre-populated envelope file. Tests can mutate via /admin/secrets."""
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({"auth_token": "secret-token-abc", "secrets": {"EXISTING": "old_value"}}))
    return path


@pytest.fixture
def config_file(tmp_path):
    """Path the /admin/config endpoint will write to."""
    return tmp_path / "config.json"


@pytest.fixture
def reload_calls():
    """Sentinel list — appended to whenever the admin reload_fn is called."""
    return []


@pytest.fixture
def app(secrets_file, config_file, reload_calls):
    return admin.make_admin_app(
        auth_token="secret-token-abc",
        secrets_path=secrets_file,
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
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/health",
        headers={"Authorization": "Bearer secret-token-ab"},
    )
    assert resp.status == 401


# ---- /admin/secrets: happy path ----

async def test_set_secret_writes_file_and_reloads(
    aiohttp_client, app, secrets_file, reload_calls
):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "GITHUB_PAT", "value": "ghp_xxx"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body == {"ok": True, "name": "GITHUB_PAT", "reloading": True}

    on_disk = json.loads(secrets_file.read_text())
    assert on_disk["secrets"]["GITHUB_PAT"] == "ghp_xxx"
    # Pre-existing secret preserved
    assert on_disk["secrets"]["EXISTING"] == "old_value"
    # auth_token preserved (load-bearing — supervisor re-pipes this on reload)
    assert on_disk["auth_token"] == "secret-token-abc"
    assert reload_calls == [True]


async def test_set_secret_overwrites(aiohttp_client, app, secrets_file):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "EXISTING", "value": "new_value"},
    )
    assert resp.status == 200
    on_disk = json.loads(secrets_file.read_text())
    assert on_disk["secrets"]["EXISTING"] == "new_value"


async def test_set_secret_multiline_value(aiohttp_client, app, secrets_file):
    """PEM-shaped values with embedded newlines should round-trip."""
    pem = "-----BEGIN-----\nbody line\n-----END-----"
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "TLS_KEY", "value": pem},
    )
    assert resp.status == 200
    on_disk = json.loads(secrets_file.read_text())
    assert on_disk["secrets"]["TLS_KEY"] == pem


# ---- /admin/secrets: validation ----

async def test_set_secret_requires_auth(aiohttp_client, app, reload_calls):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        json={"name": "X", "value": "y"},
    )
    assert resp.status == 401
    assert reload_calls == []  # no reload on failed auth


async def test_set_secret_invalid_name(aiohttp_client, app, reload_calls):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "has-dashes", "value": "y"},
    )
    assert resp.status == 400
    assert reload_calls == []


async def test_set_secret_empty_name(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "", "value": "y"},
    )
    assert resp.status == 400


async def test_set_secret_missing_value(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "X"},
    )
    assert resp.status == 400


async def test_set_secret_empty_value(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "X", "value": ""},
    )
    assert resp.status == 400


async def test_set_secret_non_string_value(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json={"name": "X", "value": 42},
    )
    assert resp.status == 400


async def test_set_secret_malformed_json(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={
            "Authorization": "Bearer secret-token-abc",
            "Content-Type": "application/json",
        },
        data=b"not json",
    )
    assert resp.status == 400


async def test_set_secret_non_object_body(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/secrets",
        headers={"Authorization": "Bearer secret-token-abc"},
        json=[1, 2, 3],
    )
    assert resp.status == 400


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
    body = await resp.json()
    assert body == {"ok": True, "reloading": True}

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
