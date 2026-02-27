"""
Category C — Security hardening tests.

Tests:
  1. CSP header contains 'frame-ancestors none'
  2. HSTS header present with max-age >= 1 year
  3. CORS rejects requests from an unlisted origin
  4. All admin endpoints return 401 without credentials
  5. validate_secrets() raises RuntimeError when ADMIN_API_KEY is too short
"""
import os
import pytest
from unittest.mock import patch


# ── 1. Content-Security-Policy ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_csp_includes_frame_ancestors_none(client, db_session):
    """CSP header must contain 'frame-ancestors none' to prevent clickjacking."""
    res = await client.get("/health")
    csp = res.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, (
        f"CSP missing 'frame-ancestors none'. Got: {csp!r}"
    )


# ── 2. HTTP Strict-Transport-Security ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_hsts_header_present(client, db_session):
    """HSTS header must be present with a max-age of at least 1 year."""
    res = await client.get("/health")
    hsts = res.headers.get("strict-transport-security", "")
    assert "max-age=" in hsts, (
        f"HSTS header missing or malformed. Got: {hsts!r}"
    )
    max_age_str = hsts.split("max-age=")[1].split(";")[0].strip()
    max_age = int(max_age_str)
    assert max_age >= 31_536_000, (
        f"HSTS max-age {max_age} is less than 1 year (31536000 seconds)"
    )


# ── 3. CORS origin allowlist ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cors_rejects_unknown_origin(client, db_session):
    """Requests from an unlisted origin must not receive Access-Control-Allow-Origin."""
    res = await client.get(
        "/health",
        headers={"Origin": "https://evil.com"},
    )
    acao = res.headers.get("access-control-allow-origin", "")
    assert acao != "https://evil.com", (
        f"CORS should not allow 'https://evil.com'. "
        f"Got Access-Control-Allow-Origin: {acao!r}"
    )


# ── 4. Admin auth enforcement ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_endpoints_require_auth(client, db_session):
    """Admin routes must return 401 when no credentials are supplied."""
    protected = [
        ("GET",  "/admin/licenses"),
        ("GET",  "/admin/audit-log"),
        ("GET",  "/admin/analytics"),
        ("GET",  "/admin/anomalies"),
    ]
    for method, path in protected:
        res = await client.request(method, path)
        assert res.status_code == 401, (
            f"{method} {path} returned {res.status_code}, expected 401"
        )


# ── 5. Startup secret validator ───────────────────────────────────────────────

def test_startup_secret_too_short_raises():
    """validate_secrets() must raise RuntimeError when ADMIN_API_KEY is too short."""
    import config

    with patch.object(config, "ADMIN_API_KEY", "tooshort"):
        with pytest.raises(RuntimeError, match="ADMIN_API_KEY"):
            config.validate_secrets()
