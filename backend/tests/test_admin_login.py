"""
Tests for POST /admin/login (TOTP / admin session JWT flow).
"""
import pytest


# ── Login returns JWT ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_login_valid_key_returns_token(client, db_session):
    """Valid API key → 200 with token and expires_in."""
    resp = await client.post("/admin/login?api_key=test-admin-key")
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["expires_in"] == 900


@pytest.mark.asyncio
async def test_admin_login_wrong_key_returns_401(client, db_session):
    """Wrong API key → 401."""
    resp = await client.post("/admin/login?api_key=wrong-key")
    assert resp.status_code == 401


# ── Bearer token grants admin access ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_bearer_token_grants_admin_access(client, db_session):
    """JWT from /admin/login works as Authorization: Bearer on admin endpoints."""
    login = await client.post("/admin/login?api_key=test-admin-key")
    assert login.status_code == 200
    token = login.json()["token"]

    res = await client.get(
        "/admin/licenses",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_invalid_bearer_token_returns_401(client, db_session):
    """Malformed Bearer token → 401."""
    res = await client.get(
        "/admin/licenses",
        headers={"Authorization": "Bearer this.is.not.valid"},
    )
    assert res.status_code == 401


# ── TOTP setup endpoint ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_totp_setup_without_secret_returns_disabled(client, db_session):
    """Without ADMIN_TOTP_SECRET set, /admin/totp/setup returns enabled=false."""
    res = await client.get(
        "/admin/totp/setup",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False
