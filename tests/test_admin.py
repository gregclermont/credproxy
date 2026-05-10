"""Tests for the merged HTTP API: admin (bearer-gated) + bootstrap routes."""
import json

import pytest
from aiohttp import web

import admin
import bootstrap
from config import Substitution, YamlCredentials


@pytest.fixture
def state(monkeypatch, tmp_path):
    """Fresh AppState; TOKEN_PATH/CONFIG_PATH redirected to tmp_path."""
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    return admin.AppState(token="established")


@pytest.fixture
def app(state):
    app = web.Application(
        middlewares=[admin.no_store, admin.fetch_metadata_guard]
    )
    app[admin.STATE_KEY] = state
    app.router.add_routes(admin.admin_routes)
    app.router.add_routes(bootstrap.bootstrap_routes)
    return app


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


# ---- load_initial_state ----

def test_load_initial_state_missing_token_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    with pytest.raises(SystemExit, match="missing"):
        admin.load_initial_state()


def test_load_initial_state_empty_token_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("")
    with pytest.raises(SystemExit, match="empty"):
        admin.load_initial_state()


def test_load_initial_state_token_only_no_config(monkeypatch, tmp_path):
    """Token present, config absent -> proxy starts with empty intercept set."""
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("xyz\n")
    state = admin.load_initial_state()
    assert state.token == "xyz"
    assert state.creds.intercept_hosts() == set()


def test_load_initial_state_token_and_config(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("xyz")
    (tmp_path / "config.json").write_text(json.dumps(VALID_CONFIG))
    state = admin.load_initial_state()
    assert state.token == "xyz"
    assert state.creds.intercept_hosts() == {"api.github.com"}


def test_load_initial_state_invalid_config_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("xyz")
    (tmp_path / "config.json").write_text(json.dumps({"not-hosts": {}}))
    with pytest.raises(SystemExit, match="persisted config invalid"):
        admin.load_initial_state()


# ---- /admin/config: bearer auth ----

async def test_post_with_correct_token_reloads(aiohttp_client, app, state):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"},
        json=VALID_CONFIG,
    )
    assert resp.status == 200
    assert await resp.json() == {"ok": True, "reloaded": True}
    assert "api.github.com" in state.creds.intercept_hosts()
    assert json.loads(admin.CONFIG_PATH.read_text()) == VALID_CONFIG


async def test_post_no_authorization_header_401(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post("/admin/config", json=VALID_CONFIG)
    assert resp.status == 401


async def test_post_non_bearer_scheme_401(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Basic c2VjcmV0"},
        json=VALID_CONFIG,
    )
    assert resp.status == 401


async def test_post_with_wrong_token_401(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer wrong"},
        json=VALID_CONFIG,
    )
    assert resp.status == 401


async def test_post_close_match_token_401(aiohttp_client, app, state):
    """Off-by-one-character token must still 401 (no prefix-match leak)."""
    state.token = "established-token-abc"
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established-token-ab"},
        json=VALID_CONFIG,
    )
    assert resp.status == 401


async def test_post_wrong_token_beats_bad_body(aiohttp_client, app):
    """Auth check must precede body parsing/validation: an attacker
    sending a bogus body should not be able to fingerprint schema
    errors (400) before being rejected for auth (401)."""
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={
            "Authorization": "Bearer wrong",
            "Content-Type": "application/json",
        },
        data=b"not json",
    )
    assert resp.status == 401

    resp2 = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer wrong"},
        json={"not-hosts": {}},
    )
    assert resp2.status == 401


async def test_post_invalid_json_400(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={
            "Authorization": "Bearer established",
            "Content-Type": "application/json",
        },
        data=b"not json",
    )
    assert resp.status == 400


async def test_post_invalid_config_does_not_overwrite(aiohttp_client, app, state):
    """Bad config validation -> 400 -> on-disk + in-memory state untouched."""
    admin.CONFIG_PATH.write_text(json.dumps(VALID_CONFIG))
    initial_creds = state.creds
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"},
        json={"not-hosts": {}},
    )
    assert resp.status == 400
    assert json.loads(admin.CONFIG_PATH.read_text()) == VALID_CONFIG
    assert state.creds is initial_creds


async def test_post_unresolved_secret_rejected(aiohttp_client, app):
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
        headers={"Authorization": "Bearer established"},
        json=bad,
    )
    assert resp.status == 400
    body = await resp.json()
    assert "GITHUB_PAT" in body["error"]


# ---- fetch_metadata_guard ----

async def test_sfs_cross_site_rejected(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/health", headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert resp.status == 403


async def test_sfs_same_site_rejected(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/health", headers={"Sec-Fetch-Site": "same-site"}
    )
    assert resp.status == 403


async def test_sfs_same_origin_allowed(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/health", headers={"Sec-Fetch-Site": "same-origin"}
    )
    assert resp.status == 200


async def test_sfs_none_allowed(aiohttp_client, app):
    """Sec-Fetch-Site: none -- address-bar / bookmark fetches."""
    client = await aiohttp_client(app)
    resp = await client.get(
        "/health", headers={"Sec-Fetch-Site": "none"}
    )
    assert resp.status == 200


async def test_sfs_missing_allowed(aiohttp_client, app):
    """Non-browser clients (curl, host CLI) don't send Sec-Fetch-Site."""
    client = await aiohttp_client(app)
    resp = await client.get("/health")
    assert resp.status == 200


# ---- bootstrap routes on the merged listener ----

async def test_health_route(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/health")
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True


async def test_setup_route(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    assert resp.status == 200
    body = await resp.json()
    assert body["ca_url"] == "http://proxy.local/ca.crt"


async def test_domains_reflects_state(aiohttp_client, app, state):
    state.creds = YamlCredentials({"api.github.com": []})
    client = await aiohttp_client(app)
    resp = await client.get("/domains")
    assert resp.status == 200
    assert await resp.json() == {"intercept": ["api.github.com"]}


async def test_tokens_reflects_state(aiohttp_client, app, state):
    state.creds = YamlCredentials(
        {"api.github.com": [Substitution("Authorization", "ph", "real")]}
    )
    client = await aiohttp_client(app)
    resp = await client.get("/tokens")
    assert resp.status == 200
    assert await resp.json() == {"api.github.com": {"Authorization": "ph"}}


async def test_no_store_header_present(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/health")
    assert resp.headers.get("Cache-Control") == "no-store"
