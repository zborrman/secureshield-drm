"""
Dynamic Geofencing Tests
Covers: allowed_countries restriction on /verify-license, /analytics/start,
        and PATCH /admin/licenses/{invoice_id}/geo.

In tests the client IP resolves to "testclient" (httpx ASGI transport).
geo_service._is_private("testclient") → True → country = "XX".

Test matrix:
  - No restriction (NULL)        → all countries pass
  - allowed_countries="XX"       → testclient is allowed
  - allowed_countries="US"       → testclient ("XX") is blocked
  - allowed_countries="US,XX,GB" → testclient ("XX") is allowed (multi-country)
  - PATCH updates restriction live
  - analytics/start also enforces the geofence
"""
import pytest
import secrets
from sqlalchemy.future import select
import models


# ── 1. Unrestricted license ───────────────────────────────────

@pytest.mark.asyncio
async def test_geo_unrestricted_license_allows_any_region(admin_client, client, db_session):
    """License without allowed_countries must be accessible from any region."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_open&is_paid=true"
    )
    plain_key = res.json()["plain_key_to_copy"]

    verify = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert verify.status_code == 200


# ── 2. Allowed region (local IP → "XX") ──────────────────────

@pytest.mark.asyncio
async def test_geo_allows_when_country_matches(admin_client, client, db_session):
    """License restricted to 'XX' must allow testclient (local IP → 'XX')."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_local&allowed_countries=XX&is_paid=true"
    )
    plain_key = res.json()["plain_key_to_copy"]

    verify = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert verify.status_code == 200


# ── 3. Blocked region ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_geo_blocks_when_country_not_in_list(admin_client, client, db_session):
    """License restricted to 'US' must block testclient (resolves to 'XX')."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_us&allowed_countries=US"
    )
    plain_key = res.json()["plain_key_to_copy"]

    verify = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert verify.status_code == 403
    assert "region" in verify.json()["detail"].lower()

    # GEO block must be recorded in audit log
    rows = await db_session.execute(
        select(models.AuditLog).where(models.AuditLog.invoice_id == invoice_id)
    )
    entry = rows.scalars().first()
    assert entry is not None
    assert "GEO_BLOCKED" in entry.user_agent


# ── 4. Multi-country list ─────────────────────────────────────

@pytest.mark.asyncio
async def test_geo_allows_when_country_in_multi_list(admin_client, client, db_session):
    """License with 'US,XX,GB' must allow testclient ('XX' matches the list)."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_multi&allowed_countries=US,XX,GB&is_paid=true"
    )
    plain_key = res.json()["plain_key_to_copy"]

    verify = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert verify.status_code == 200


# ── 5. PATCH updates restriction live ────────────────────────

@pytest.mark.asyncio
async def test_geo_patch_updates_restriction_immediately(admin_client, client, db_session):
    """PATCH /admin/licenses/{id}/geo must enforce the new rule on the next request."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_patch&is_paid=true"
    )
    plain_key = res.json()["plain_key_to_copy"]

    # Initially unrestricted → passes
    first = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert first.status_code == 200

    # Admin restricts to US only
    patch = await admin_client.patch(
        f"/admin/licenses/{invoice_id}/geo?allowed_countries=US"
    )
    assert patch.status_code == 200
    assert patch.json()["allowed_countries"] == "US"

    # Now testclient ("XX") is blocked
    second = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert second.status_code == 403

    # Admin lifts the restriction
    patch2 = await admin_client.patch(
        f"/admin/licenses/{invoice_id}/geo?allowed_countries="
    )
    assert patch2.status_code == 200
    assert patch2.json()["allowed_countries"] is None

    # Unrestricted again → passes
    third = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert third.status_code == 200


# ── 6. analytics/start enforces geofence ─────────────────────

@pytest.mark.asyncio
async def test_geo_analytics_start_enforces_geofence(admin_client, client, db_session):
    """POST /analytics/start must also return 403 when IP is outside allowed region."""
    invoice_id = f"GEO-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_ana&allowed_countries=US"
    )

    ana = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-geo"},
    )
    assert ana.status_code == 403
    assert "region" in ana.json()["detail"].lower()
