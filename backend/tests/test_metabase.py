"""
Metabase embedded analytics integration tests.

No real Metabase instance is required — all tests work against the
/admin/metabase/embed-token endpoint only and verify JWT correctness
via PyJWT decoding.

Tests:
  1. Embed token endpoint returns 200 with embed_url and token
  2. Token is a valid HS256 JWT containing the requested dashboard_id
  3. Endpoint requires admin authentication (401 without key)
  4. Returns 503 when METABASE_SECRET_KEY is not configured
"""

from __future__ import annotations

import os
from unittest.mock import patch

import jwt as _jwt
import pytest

_ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "test-admin-key")
_TEST_SECRET = "test-metabase-secret-key-32chars!!"


# ── Test 1: happy path ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_embed_token_returns_200(client, db_session):
    """Endpoint returns 200 with embed_url, token, and dashboard_id."""
    with patch("config.METABASE_SECRET_KEY", _TEST_SECRET):
        with patch("config.METABASE_SITE_URL", "http://localhost:3002"):
            resp = await client.get(
                "/admin/metabase/embed-token?dashboard_id=1",
                headers={"X-Admin-Key": _ADMIN_KEY},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert "embed_url" in data
    assert "token" in data
    assert data["dashboard_id"] == 1
    assert "expires_in" in data
    assert "http://localhost:3002/embed/dashboard/" in data["embed_url"]


# ── Test 2: JWT payload correctness ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_embed_token_jwt_is_decodable(client, db_session):
    """The returned token must be a valid HS256 JWT with resource.dashboard set."""
    with patch("config.METABASE_SECRET_KEY", _TEST_SECRET):
        with patch("config.METABASE_SITE_URL", "http://localhost:3002"):
            resp = await client.get(
                "/admin/metabase/embed-token?dashboard_id=7&expires_in=300",
                headers={"X-Admin-Key": _ADMIN_KEY},
            )

    assert resp.status_code == 200
    token = resp.json()["token"]

    # Decode and verify payload without requiring network access
    payload = _jwt.decode(token, _TEST_SECRET, algorithms=["HS256"])
    assert payload["resource"]["dashboard"] == 7
    assert payload["params"] == {}
    assert "exp" in payload


# ── Test 3: authentication required ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_embed_token_requires_auth(client, db_session):
    """Endpoint must return 401 when no admin credentials are provided."""
    resp = await client.get("/admin/metabase/embed-token?dashboard_id=1")
    assert resp.status_code == 401


# ── Test 4: 503 when secret not configured ────────────────────────────────────

@pytest.mark.asyncio
async def test_embed_token_503_without_secret(client, db_session):
    """Endpoint must return 503 with a clear message when METABASE_SECRET_KEY is empty."""
    with patch("config.METABASE_SECRET_KEY", ""):
        resp = await client.get(
            "/admin/metabase/embed-token?dashboard_id=1",
            headers={"X-Admin-Key": _ADMIN_KEY},
        )

    assert resp.status_code == 503
    assert "METABASE_SECRET_KEY" in resp.json()["detail"]
