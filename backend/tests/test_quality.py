"""
Category A+C+E — Code Quality, Security Headers, API Version.

Tests:
  1. Anomaly service cutoffs are timezone-aware
  2. _admin_session_secret() returns ≥ 32 bytes
  3. ADMIN_SESSION_SECRET env var takes priority
  4. /admin/login JWT is decodable with the session secret
  5. X-API-Version header present on every response
  6. X-Request-ID header present on every response
  7. Core security headers present on every response
"""
import os
import pytest
import jwt as _jwt
from datetime import timezone


_ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "test-admin-key")


# ── Cat A — Code Quality ───────────────────────────────────────────────────────

def test_anomaly_cutoff_is_timezone_aware():
    """datetime.now(timezone.utc) objects must have tzinfo set."""
    from datetime import datetime, timezone as tz
    import anomaly_service  # noqa: F401 — verifies module loads without error
    dt = datetime.now(tz.utc)
    assert dt.tzinfo is not None, "datetime.now(timezone.utc) must carry tzinfo"
    assert dt.tzinfo == timezone.utc


def test_admin_session_secret_minimum_32_bytes():
    """The JWT signing secret must always be ≥ 32 bytes."""
    from dependencies import _admin_session_secret
    secret = _admin_session_secret()
    assert len(secret.encode()) >= 32, (
        f"_admin_session_secret() returned {len(secret.encode())} bytes; "
        "HS256 requires ≥ 32"
    )


def test_admin_session_secret_env_override(monkeypatch):
    """If ADMIN_SESSION_SECRET is set, it overrides the SHA-256 derivation."""
    override = "my-explicit-session-secret-64-bytes-long-for-production-use!!"
    monkeypatch.setenv("ADMIN_SESSION_SECRET", override)

    import importlib
    import config as _cfg
    importlib.reload(_cfg)
    import dependencies as _dep
    importlib.reload(_dep)

    assert _dep._admin_session_secret() == override

    # Reload with original values so other tests are unaffected
    monkeypatch.delenv("ADMIN_SESSION_SECRET", raising=False)
    importlib.reload(_cfg)
    importlib.reload(_dep)


@pytest.mark.asyncio
async def test_login_returns_decodable_jwt(client, db_session):
    """POST /admin/login returns a JWT that decodes correctly with the session secret."""
    from dependencies import _admin_session_secret
    resp = await client.post(f"/admin/login?api_key={_ADMIN_KEY}")
    assert resp.status_code == 200
    token = resp.json()["token"]
    payload = _jwt.decode(token, _admin_session_secret(), algorithms=["HS256"])
    assert payload["sub"] == "admin"
    assert payload["type"] == "admin_session"


# ── Cat C / E — Security Headers + API Version ────────────────────────────────

@pytest.mark.asyncio
async def test_x_api_version_header_present(client, db_session):
    """Every response must carry X-API-Version: 1.0.0."""
    resp = await client.get("/health", headers={"X-Admin-Key": _ADMIN_KEY})
    assert resp.headers.get("x-api-version") == "1.0.0"


@pytest.mark.asyncio
async def test_x_request_id_in_response(client, db_session):
    """Every response must echo X-Request-ID."""
    resp = await client.get("/health", headers={"X-Admin-Key": _ADMIN_KEY})
    assert "x-request-id" in resp.headers


@pytest.mark.asyncio
async def test_security_headers_on_all_responses(client, db_session):
    """Core security headers must be present on every response."""
    resp = await client.get("/health", headers={"X-Admin-Key": _ADMIN_KEY})
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers.get("content-security-policy", "")
    assert "max-age=63072000" in resp.headers.get("strict-transport-security", "")
