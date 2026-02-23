"""
Performance tests — Week 3 hardening.

Covers:
  T1: Prometheus metrics endpoint + custom drm_license_verifications_total counter
  T2: Redis license cache (set on miss, hit avoids DB, invalidated on payment + geo update)
  T3: Cursor pagination for /admin/audit-log and /admin/analytics
  T4: S3 presigned download URL for vault content
"""
import re
import pytest
from sqlalchemy.future import select

import redis_service
import models


# ── helpers ───────────────────────────────────────────────────────────────────

def _counter_value(metrics_text: str, label: str) -> float:
    """Extract current value of drm_license_verifications_total for a given label."""
    pattern = rf'drm_license_verifications_total\{{[^}}]*status="{label}"[^}}]*\}} (\S+)'
    m = re.search(pattern, metrics_text)
    return float(m.group(1)) if m else 0.0


# ── T1: Prometheus metrics ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_metrics_endpoint_returns_200(client, db_session):
    """/metrics must return 200 with Prometheus text format content-type."""
    res = await client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]


@pytest.mark.asyncio
async def test_verify_counter_increments_on_success(admin_client, client, db_session):
    """A successful verify-license must increment the 'success' counter by 1."""
    invoice_id = "PERF-CTR-SUC-01"
    create = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=ctr_tester&is_paid=true"
    )
    assert create.status_code == 201
    plain_key = create.json()["plain_key_to_copy"]

    before = _counter_value((await client.get("/metrics")).text, "success")
    await client.post("/verify-license", params={"invoice_id": invoice_id, "input_key": plain_key})
    after = _counter_value((await client.get("/metrics")).text, "success")

    assert after == before + 1


@pytest.mark.asyncio
async def test_verify_counter_increments_on_failure(admin_client, client, db_session):
    """A failed verify-license must increment the 'failure' counter by 1."""
    invoice_id = "PERF-CTR-FAIL-01"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=ctr_fail_tester&is_paid=true"
    )

    before = _counter_value((await client.get("/metrics")).text, "failure")
    await client.post("/verify-license", params={"invoice_id": invoice_id, "input_key": "wrong"})
    after = _counter_value((await client.get("/metrics")).text, "failure")

    assert after == before + 1


# ── T2: Redis license cache ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_license_sets_redis_cache(admin_client, client, db_session, fake_redis):
    """After a verify-license call, the license must be cached in Redis."""
    invoice_id = "PERF-CACHE-SET-01"
    create = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=cache_tester&is_paid=true"
    )
    plain_key = create.json()["plain_key_to_copy"]

    # Before: no cache entry
    assert await redis_service.cache_get(f"lic:{invoice_id}") is None

    await client.post("/verify-license", params={"invoice_id": invoice_id, "input_key": plain_key})

    # After: cache entry must exist
    cached = await redis_service.cache_get(f"lic:{invoice_id}")
    assert cached is not None
    assert cached["is_paid"] is True


@pytest.mark.asyncio
async def test_second_verify_uses_cache(admin_client, client, db_session, fake_redis):
    """A second verify-license call with a cached license must return 200 without DB miss."""
    invoice_id = "PERF-CACHE-HIT-01"
    create = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=cache_hit&is_paid=true"
    )
    plain_key = create.json()["plain_key_to_copy"]

    # First call — populates cache
    r1 = await client.post(
        "/verify-license", params={"invoice_id": invoice_id, "input_key": plain_key}
    )
    assert r1.status_code == 200

    # Second call — should hit cache (still 200, no errors)
    r2 = await client.post(
        "/verify-license", params={"invoice_id": invoice_id, "input_key": plain_key}
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "success"


@pytest.mark.asyncio
async def test_payment_invalidates_license_cache(admin_client, client, db_session, fake_redis):
    """handle_payment_success must delete the cached license entry."""
    invoice_id = "PERF-CACHE-INV-PAY-01"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=inv_pay_tester"
    )

    # Seed a stale cache entry manually (is_paid=False)
    await redis_service.cache_set(f"lic:{invoice_id}", {
        "is_paid": False, "license_key": "hash", "allowed_countries": None, "owner_id": "x",
    })
    assert await redis_service.cache_get(f"lic:{invoice_id}") is not None

    # Simulate payment
    from stripe_service import handle_payment_success
    await handle_payment_success(invoice_id)

    # Cache must be gone
    assert await redis_service.cache_get(f"lic:{invoice_id}") is None


@pytest.mark.asyncio
async def test_geo_update_invalidates_license_cache(admin_client, client, db_session, fake_redis):
    """PATCH /admin/licenses/{id}/geo must invalidate the license cache."""
    invoice_id = "PERF-CACHE-INV-GEO-01"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=geo_inv_tester&is_paid=true"
    )

    # Seed a cache entry
    await redis_service.cache_set(f"lic:{invoice_id}", {
        "is_paid": True, "license_key": "hash", "allowed_countries": None, "owner_id": "x",
    })
    assert await redis_service.cache_get(f"lic:{invoice_id}") is not None

    # Update geo restriction
    res = await admin_client.patch(
        f"/admin/licenses/{invoice_id}/geo",
        params={"allowed_countries": "US"},
    )
    assert res.status_code == 200

    # Cache must be gone
    assert await redis_service.cache_get(f"lic:{invoice_id}") is None


# ── T3: Cursor pagination ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_log_returns_x_next_cursor_header(admin_client, client, db_session):
    """GET /admin/audit-log must return X-Next-Cursor header when rows are present."""
    invoice_id = "PERF-CURSOR-AUD-01"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=cursor_aud&is_paid=true"
    )
    # Generate some audit rows via failed verify attempts
    for _ in range(3):
        await client.post(
            "/verify-license", params={"invoice_id": invoice_id, "input_key": "wrong"}
        )

    res = await admin_client.get("/admin/audit-log?limit=2")
    assert res.status_code == 200
    assert "x-next-cursor" in res.headers


@pytest.mark.asyncio
async def test_audit_log_before_id_returns_earlier_rows(admin_client, client, db_session):
    """before_id cursor must return rows with IDs strictly less than the cursor."""
    invoice_id = "PERF-CURSOR-AUD-02"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=cursor_aud2&is_paid=true"
    )
    for _ in range(5):
        await client.post(
            "/verify-license", params={"invoice_id": invoice_id, "input_key": "bad"}
        )

    # First page
    page1 = await admin_client.get("/admin/audit-log?limit=3")
    assert page1.status_code == 200
    cursor = int(page1.headers["x-next-cursor"])
    rows1 = page1.json()
    assert len(rows1) == 3

    # Second page
    page2 = await admin_client.get(f"/admin/audit-log?before_id={cursor}&limit=10")
    assert page2.status_code == 200
    rows2 = page2.json()
    # All IDs in page2 must be less than the cursor
    assert all(r["id"] < cursor for r in rows2)
    # No row in page2 should appear in page1
    ids1 = {r["id"] for r in rows1}
    ids2 = {r["id"] for r in rows2}
    assert ids1.isdisjoint(ids2)


@pytest.mark.asyncio
async def test_analytics_cursor_pagination(admin_client, client, db_session):
    """GET /admin/analytics must support before_id cursor pagination."""
    invoice_id = "PERF-CURSOR-ANA-01"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=cursor_ana&is_paid=true"
    )
    for i in range(4):
        await client.post(
            "/analytics/start",
            params={"invoice_id": invoice_id, "content_id": f"doc-{i}"},
        )

    page1 = await admin_client.get("/admin/analytics?limit=2")
    assert page1.status_code == 200
    assert "x-next-cursor" in page1.headers
    cursor = int(page1.headers["x-next-cursor"])

    page2 = await admin_client.get(f"/admin/analytics?before_id={cursor}&limit=10")
    assert page2.status_code == 200
    rows2 = page2.json()
    assert all(r["id"] < cursor for r in rows2)


# ── T4: S3 presigned download URL ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vault_presign_returns_url_and_metadata(admin_client, db_session, mock_s3):
    """GET /admin/vault/{id}/presign must return a URL string + metadata."""
    # Upload a file
    upload_res = await admin_client.post(
        "/admin/vault/upload",
        files={"file": ("report.pdf", b"PDF content", "application/pdf")},
        data={"description": "test doc"},
    )
    assert upload_res.status_code == 201
    content_id = upload_res.json()["content_id"]

    # Request presigned URL
    res = await admin_client.get(f"/admin/vault/{content_id}/presign")
    assert res.status_code == 200
    body = res.json()
    assert "url" in body
    assert isinstance(body["url"], str)
    assert len(body["url"]) > 0
    assert body["content_id"] == content_id
    assert body["filename"] == "report.pdf"
    assert body["expires_in"] == 300  # default


@pytest.mark.asyncio
async def test_vault_presign_custom_expires_in(admin_client, db_session, mock_s3):
    """GET /admin/vault/{id}/presign?expires_in=600 must respect the parameter."""
    upload_res = await admin_client.post(
        "/admin/vault/upload",
        files={"file": ("doc.txt", b"hello", "text/plain")},
    )
    content_id = upload_res.json()["content_id"]

    res = await admin_client.get(f"/admin/vault/{content_id}/presign?expires_in=600")
    assert res.status_code == 200
    assert res.json()["expires_in"] == 600


@pytest.mark.asyncio
async def test_vault_presign_404_for_unknown_content(admin_client, db_session, mock_s3):
    """GET /admin/vault/{id}/presign with unknown ID must return 404."""
    res = await admin_client.get("/admin/vault/nonexistent-uuid-999/presign")
    assert res.status_code == 404
