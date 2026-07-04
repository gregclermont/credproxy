"""Tests for the merged HTTP API: admin (bearer-gated) + bootstrap routes."""
import json

import pytest
from aiohttp import web

import admin
import bootstrap
import schemes
from config import BindingCredentials, InwardBinding, Transform


def _xform(placeholder, real, *, header="Authorization", name="b"):
    """A bearer Transform for tests."""
    return Transform(name, schemes.SCHEMES["bearer"], {"header": header},
                     placeholder, {"value": real})


@pytest.fixture
def state(monkeypatch, tmp_path):
    """Fresh AppState; TOKEN_PATH/CONFIG_PATH redirected to tmp_path,
    token file pre-populated so admin_config's per-call read succeeds."""
    token_path = tmp_path / "auth.token"
    monkeypatch.setattr(admin, "TOKEN_PATH", token_path)
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    token_path.write_text("established")
    return admin.AppState()


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
    "bindings": [
        {
            "name": "github-env",
            "hosts": ["api.github.com"],
            "scheme": "bearer",
            "params": {"header": "Authorization"},
            "placeholder": "credproxy_test",
            "secret": {"value": "github_pat_real"},
            "env": "GITHUB_TOKEN",
        }
    ]
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
    assert state.creds.intercept_hosts() == set()


def test_load_initial_state_token_and_config(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("xyz")
    (tmp_path / "config.json").write_text(json.dumps(VALID_CONFIG))
    state = admin.load_initial_state()
    assert state.creds.intercept_hosts() == {"api.github.com"}


def test_load_initial_state_invalid_config_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(admin, "TOKEN_PATH", tmp_path / "auth.token")
    monkeypatch.setattr(admin, "CONFIG_PATH", tmp_path / "config.json")
    (tmp_path / "auth.token").write_text("xyz")
    (tmp_path / "config.json").write_text(json.dumps({"not-bindings": {}}))
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
    assert await resp.json() == {"ok": True}
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


async def test_post_close_match_token_401(aiohttp_client, app):
    """Off-by-one-character token must still 401 (no prefix-match leak)."""
    admin.TOKEN_PATH.write_text("established-token-abc")
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
        json={"not-bindings": {}},
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
        json={"not-bindings": {}},
    )
    assert resp.status == 400
    assert json.loads(admin.CONFIG_PATH.read_text()) == VALID_CONFIG
    assert state.creds is initial_creds


async def test_post_unresolved_secret_rejected(aiohttp_client, app):
    bad = {"bindings": [
        {"name": "b", "hosts": ["api.github.com"], "scheme": "bearer",
         "placeholder": "ph", "secret": {"value": "${secret:GITHUB_PAT}"}}
    ]}
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"},
        json=bad,
    )
    assert resp.status == 400
    body = await resp.json()
    assert "GITHUB_PAT" in body["error"]


async def test_token_rotation_takes_effect_without_restart(aiohttp_client, app):
    """Rewriting TOKEN_PATH mid-flight: the old value 401s on the next
    request, the new value works -- no app restart required."""
    client = await aiohttp_client(app)

    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"},
        json=VALID_CONFIG,
    )
    assert resp.status == 200

    admin.TOKEN_PATH.write_text("rotated")

    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"},
        json=VALID_CONFIG,
    )
    assert resp.status == 401

    resp = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer rotated"},
        json=VALID_CONFIG,
    )
    assert resp.status == 200


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


async def test_index_route_map(aiohttp_client, app):
    """Bare GET / returns a plain-text route map instead of a 404."""
    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert resp.status == 200
    assert resp.content_type == "text/plain"
    text = await resp.text()
    assert "/setup" in text and "/bootstrap.sh" in text


async def test_setup_static_fields(aiohttp_client, app):
    """Static fields present even with an empty credentials state."""
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    assert resp.status == 200
    # Pretty-printed with a trailing newline for clean `curl` output.
    text = await resp.text()
    assert text.endswith("\n")
    assert "\n  " in text  # indented
    body = await resp.json()
    assert body["ca_url"] == "http://proxy.local/ca.crt"
    assert body["version"] == bootstrap.VERSION
    assert body["env"] == bootstrap.CA_ENV
    assert body["intercept_hosts"] == []
    assert body["bindings"] == []


async def test_setup_reflects_state(aiohttp_client, app, state):
    """After a config push, /setup returns the inward bindings shape."""
    state.creds = BindingCredentials(
        {"api.github.com": [_xform("ph", "real")]},
        [InwardBinding(name="gh", placeholder="ph", env="GH_TOKEN",
                       scheme="bearer", params={"header": "Authorization"},
                       hosts=["api.github.com"])],
    )
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    assert resp.status == 200
    body = await resp.json()
    assert body["intercept_hosts"] == ["api.github.com"]
    bindings = body["bindings"]
    assert len(bindings) == 1
    b = bindings[0]
    assert b["name"] == "gh"
    assert b["placeholder"] == "ph"
    assert b["env"] == "GH_TOKEN"
    assert b["scheme"] == "bearer"
    assert b["params"] == {"header": "Authorization"}
    assert b["hosts"] == ["api.github.com"]


async def test_setup_exposes_workspace_name(aiohttp_client, app, monkeypatch):
    """The workspace's own name is exposed for self-identification (e.g. PS1)."""
    monkeypatch.setenv("CREDPROXY_WORKSPACE", "myproj")
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    body = await resp.json()
    assert body["workspace"] == "myproj"


async def test_setup_workspace_name_absent_is_null(aiohttp_client, app, monkeypatch):
    """Gracefully null when the env var is unset (e.g. a proxy created before
    this field existed)."""
    monkeypatch.delenv("CREDPROXY_WORKSPACE", raising=False)
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    body = await resp.json()
    assert body["workspace"] is None


async def test_setup_least_disclosure(aiohttp_client, app, state):
    """Inward API: real credential values must NOT appear in /setup response."""
    state.creds = BindingCredentials(
        {"api.github.com": [_xform("ph_sentinel", "super_secret_real")]},
        [InwardBinding(name="gh", placeholder="ph_sentinel", env=None,
                       scheme="bearer", params={"header": "Authorization"},
                       hosts=["api.github.com"])],
    )
    client = await aiohttp_client(app)
    resp = await client.get("/setup")
    body_text = await resp.text()
    assert "super_secret_real" not in body_text
    # provider and secret-id are CLI-side only; confirm they also can't appear
    # (they are never sent to the proxy in the push model).


# ---- bootstrap CA bundle: combined system roots + proxy CA (issue #10) -------


def test_bootstrap_sh_is_valid_posix_sh():
    """The embedded bootstrap script must be valid POSIX sh -- guards the
    escaping of the Python string literal (e.g. the `\\` line continuation)."""
    import subprocess
    r = subprocess.run(["sh", "-n"], input=bootstrap.BOOTSTRAP_SH,
                       text=True, capture_output=True)
    assert r.returncode == 0, r.stderr


def test_bootstrap_sh_builds_combined_ca_bundle():
    """The CA env-var bundle (/tmp/proxy-ca.crt) is the system roots PLUS the
    proxy CA, so env-var-only tools (mise/node/cargo/aws/requests) verify
    passthrough hosts too -- not just intercepted ones."""
    sh = bootstrap.BOOTSTRAP_SH
    # The proxy CA is downloaded to its OWN file, kept apart from the bundle.
    assert 'curl -sf -o "$CA_ONLY" http://proxy.local/ca.crt' in sh
    # Combined bundle = a system root bundle ++ the proxy CA.
    assert 'cat "$SYS_CA" "$CA_ONLY" > "$CA_PATH"' in sh
    # Both Debian/Ubuntu/Alpine and RHEL/Fedora root-bundle locations are probed.
    assert "/etc/ssl/certs/ca-certificates.crt" in sh
    assert "/etc/pki/tls/certs/ca-bundle.crt" in sh


def test_bootstrap_sh_system_store_installs_only_proxy_ca():
    """Regression guard: the system-store step installs the SINGLE proxy CA, not
    the combined bundle -- else update-ca-certificates would re-append every
    system root to the system store."""
    sh = bootstrap.BOOTSTRAP_SH
    assert 'cp "$CA_ONLY" /usr/local/share/ca-certificates/proxy.crt' in sh
    assert 'cp "$CA_PATH" /usr/local/share/ca-certificates/proxy.crt' not in sh


def test_ca_env_points_at_combined_bundle():
    """Every CA env var points at the combined bundle, never the proxy-only file
    -- the bundle is what makes both intercepted and passthrough hosts verify."""
    assert set(bootstrap.CA_ENV.values()) == {"/tmp/proxy-ca.crt"}


def test_workspace_bindings_function():
    """Unit test for the bootstrap.workspace_bindings free function."""
    creds = BindingCredentials(
        {
            "api.github.com": [_xform("ph1", "r1")],
            "api.example.com": [_xform("ph2", "r2", header="X-API-Key")],
        },
        [
            InwardBinding(name="gh", placeholder="ph1", env="GH_TOKEN",
                          scheme="bearer", params={"header": "Authorization"},
                          hosts=["api.github.com"]),
            InwardBinding(name="ex", placeholder="ph2", env=None,
                          scheme="bearer", params={"header": "X-API-Key"},
                          hosts=["api.example.com"]),
        ],
    )
    result = bootstrap.workspace_bindings(creds)
    assert len(result) == 2
    by_name = {b["name"]: b for b in result}
    assert by_name["gh"]["placeholder"] == "ph1"
    assert by_name["gh"]["env"] == "GH_TOKEN"
    assert by_name["gh"]["scheme"] == "bearer"
    assert by_name["gh"]["params"] == {"header": "Authorization"}
    assert by_name["gh"]["hosts"] == ["api.github.com"]
    assert "real" not in by_name["gh"]
    assert "secret" not in by_name["gh"]
    assert by_name["ex"]["env"] is None


def test_workspace_bindings_empty():
    assert bootstrap.workspace_bindings(BindingCredentials({})) == []


async def test_no_store_header_present(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/health")
    assert resp.headers.get("Cache-Control") == "no-store"


# ---- GET /admin/config: loaded + fingerprint (for the enter fast path) ----


async def test_get_config_unloaded(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get(
        "/admin/config", headers={"Authorization": "Bearer established"})
    assert resp.status == 200
    assert await resp.json() == {"loaded": False, "fingerprint": None}


async def test_get_config_requires_auth(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.get("/admin/config")
    assert resp.status == 401


async def test_get_config_reports_fingerprint(aiohttp_client, app):
    client = await aiohttp_client(app)
    body = dict(VALID_CONFIG, fingerprint="abc123")
    r = await client.post(
        "/admin/config",
        headers={"Authorization": "Bearer established"}, json=body)
    assert r.status == 200
    resp = await client.get(
        "/admin/config", headers={"Authorization": "Bearer established"})
    assert resp.status == 200
    assert await resp.json() == {"loaded": True, "fingerprint": "abc123"}


# ---- /admin/rule-test (live dry-run) ----


async def test_rule_test_endpoint(aiohttp_client, app, state):
    import config
    state.creds = config.load_resolved({"bindings": [], "rules": [
        {"name": "blk", "hosts": ["api.github.com"], "action": "block",
         "methods": ["DELETE"], "path": "/repos/**"},
    ]})
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/rule-test",
        json={"method": "DELETE", "url": "https://api.github.com/repos/a/b"},
        headers={"Authorization": "Bearer established"})
    assert resp.status == 200
    data = await resp.json()
    assert data["intercepted"] is True
    assert [m["name"] for m in data["matches"]] == ["blk"]
    assert data["matches"][0]["terminal"] is True
    # a non-matching method: intercepted (union) but no rule fires
    resp2 = await client.post(
        "/admin/rule-test",
        json={"method": "GET", "url": "https://api.github.com/repos/a/b"},
        headers={"Authorization": "Bearer established"})
    assert (await resp2.json())["matches"] == []


async def test_rule_test_endpoint_requires_token(aiohttp_client, app):
    client = await aiohttp_client(app)
    resp = await client.post(
        "/admin/rule-test", json={"method": "GET", "url": "https://x.example.com/"})
    assert resp.status == 401
