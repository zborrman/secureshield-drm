"""
Week 5 — License Expiry, Proof-of-Leak Dedup, Geo-block Webhook

Tests:
  1.  Non-expired license verifies normally
  2.  Expired license returns 410 Gone on /verify-license
  3.  Expired license returns 410 Gone on /analytics/start
  4.  create-license stores expires_at
  5.  Duplicate proof-of-leak returns 409 without force
  6.  force=true regenerates report (deletes old, creates new)
  7.  Fingerprint-based reports are not subject to dedup (different invoice_id scoping)
  8.  fire_geo_block_webhook fires when GEO_WEBHOOK_URL is set
  9.  fire_geo_block_webhook swallows exceptions (fail-open)
  10. fire_geo_block_webhook is a no-op when url is empty
"""
import pytest
import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest_asyncio

from geo_service import fire_geo_block_webhook


# ── 1. Non-expired license passes ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_non_expired_license_verifies(admin_client, client, db_session):
    """License with future expires_at must verify successfully."""
    invoice_id = f"EXP-FUTURE-{secrets.token_hex(4)}"
    future = (datetime.utcnow() + timedelta(days=30)).isoformat()

    res = await admin_client.post(
        f"/admin/create-license"
        f"?invoice_id={invoice_id}&owner_id=alice&is_paid=true&expires_at={future}"
    )
    assert res.status_code == 201
    plain_key = res.json()["plain_key_to_copy"]

    res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert res.status_code == 200


# ── 2. Expired license → 410 on verify-license ───────────────────────────────

@pytest.mark.asyncio
async def test_expired_license_verify_returns_410(admin_client, client, db_session):
    """A license with expires_at in the past must return 410 Gone."""
    invoice_id = f"EXP-PAST-{secrets.token_hex(4)}"
    past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()

    res = await admin_client.post(
        f"/admin/create-license"
        f"?invoice_id={invoice_id}&owner_id=bob&is_paid=true&expires_at={past}"
    )
    assert res.status_code == 201
    plain_key = res.json()["plain_key_to_copy"]

    res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert res.status_code == 410
    assert "expired" in res.json()["detail"].lower()


# ── 3. Expired license → 410 on analytics/start ──────────────────────────────

@pytest.mark.asyncio
async def test_expired_license_analytics_start_returns_410(admin_client, client, db_session):
    """analytics/start must also reject expired licenses with 410."""
    invoice_id = f"EXP-ANA-{secrets.token_hex(4)}"
    past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()

    await admin_client.post(
        f"/admin/create-license"
        f"?invoice_id={invoice_id}&owner_id=carol&is_paid=true&expires_at={past}"
    )

    res = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-1"},
    )
    assert res.status_code == 410
    assert "expired" in res.json()["detail"].lower()


# ── 4. create-license stores expires_at ──────────────────────────────────────

@pytest.mark.asyncio
async def test_create_license_stores_expires_at(admin_client, db_session):
    """expires_at set on create-license should be persisted in DB."""
    from sqlalchemy.future import select
    import models

    invoice_id = f"EXP-STORE-{secrets.token_hex(4)}"
    future = (datetime.utcnow() + timedelta(days=7)).isoformat()

    res = await admin_client.post(
        f"/admin/create-license"
        f"?invoice_id={invoice_id}&owner_id=dave&expires_at={future}"
    )
    assert res.status_code == 201

    result = await db_session.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    assert lic is not None
    assert lic.expires_at is not None
    assert lic.expires_at > datetime.utcnow()


# ── 5. Duplicate proof-of-leak → 409 without force ───────────────────────────

@pytest.mark.asyncio
async def test_duplicate_leak_report_returns_409(admin_client, db_session):
    """Second POST /admin/proof-of-leak for the same invoice_id must return 409."""
    invoice_id = f"DEDUP-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=eve&is_paid=true"
    )

    res1 = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert res1.status_code == 201

    res2 = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert res2.status_code == 409
    assert invoice_id in res2.json()["detail"]


# ── 6. force=true regenerates report ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_force_regenerates_leak_report(admin_client, db_session):
    """force=true must delete the existing report and create a new one."""
    invoice_id = f"FORCE-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=frank&is_paid=true"
    )

    res1 = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert res1.status_code == 201
    report_id_1 = res1.json()["report_id"]

    res2 = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}&force=true")
    assert res2.status_code == 201
    report_id_2 = res2.json()["report_id"]

    # A new UUID must have been generated
    assert report_id_1 != report_id_2

    # Only one report for this invoice_id should exist now
    list_res = await admin_client.get("/admin/proof-of-leak")
    reports = [r for r in list_res.json() if r["invoice_id"] == invoice_id]
    assert len(reports) == 1
    assert reports[0]["report_id"] == report_id_2


# ── 7. Fingerprint-based reports not affected by invoice dedup ────────────────

@pytest.mark.asyncio
async def test_fingerprint_report_not_subject_to_invoice_dedup(admin_client, db_session):
    """Reports created via fingerprint (invoice_id=None) must not conflict with each other."""
    from watermark_service import generate_user_fingerprint

    # Two different owners — fingerprint lookup is per-owner, not per-invoice
    invoice_id1 = f"FP-{secrets.token_hex(4)}"
    invoice_id2 = f"FP-{secrets.token_hex(4)}"
    owner1 = f"owner_{secrets.token_hex(4)}"
    owner2 = f"owner_{secrets.token_hex(4)}"

    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id1}&owner_id={owner1}&is_paid=true"
    )
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id2}&owner_id={owner2}&is_paid=true"
    )

    fp1 = generate_user_fingerprint(owner1)
    fp2 = generate_user_fingerprint(owner2)

    res1 = await admin_client.post(f"/admin/proof-of-leak?fingerprint={fp1}")
    assert res1.status_code == 201

    # Second fingerprint-based report for a *different* owner must succeed (no conflict)
    res2 = await admin_client.post(f"/admin/proof-of-leak?fingerprint={fp2}")
    assert res2.status_code == 201


# ── 8. fire_geo_block_webhook calls the URL ───────────────────────────────────

@pytest.mark.asyncio
async def test_fire_geo_block_webhook_posts_payload():
    """Webhook must POST to the configured URL with the right payload."""
    mock_response = AsyncMock()
    mock_response.status_code = 200

    with patch("geo_service.httpx.AsyncClient") as mock_client_cls:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_instance.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_instance

        await fire_geo_block_webhook(
            url="https://example.com/webhook",
            invoice_id="INV-TEST",
            country="RU",
            ip="1.2.3.4",
        )

        mock_instance.post.assert_called_once_with(
            "https://example.com/webhook",
            json={
                "event": "geo_blocked",
                "invoice_id": "INV-TEST",
                "country": "RU",
                "ip": "1.2.3.4",
            },
        )


# ── 9. fire_geo_block_webhook swallows exceptions ─────────────────────────────

@pytest.mark.asyncio
async def test_fire_geo_block_webhook_fail_open():
    """A network error must not propagate — the function must return normally."""
    with patch("geo_service.httpx.AsyncClient") as mock_client_cls:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_instance.post = AsyncMock(side_effect=Exception("network error"))
        mock_client_cls.return_value = mock_instance

        # Must not raise
        await fire_geo_block_webhook(
            url="https://example.com/webhook",
            invoice_id="INV-TEST",
            country="RU",
            ip="1.2.3.4",
        )


# ── 10. fire_geo_block_webhook is a no-op when url is empty ──────────────────

@pytest.mark.asyncio
async def test_fire_geo_block_webhook_noop_when_url_empty():
    """Empty URL must result in no HTTP call."""
    with patch("geo_service.httpx.AsyncClient") as mock_client_cls:
        await fire_geo_block_webhook(url="", invoice_id="INV-TEST", country="RU", ip="1.2.3.4")
        mock_client_cls.assert_not_called()
