"""
Proof of Leak — Legal Evidence Generator Tests
Covers: POST /admin/proof-of-leak, GET /admin/proof-of-leak, GET /admin/proof-of-leak/{id}
"""
import hashlib
import json
import pytest
import secrets

from sqlalchemy.future import select

import models
from watermark_service import generate_user_fingerprint


# ── 1. Generate report by invoice_id ─────────────────────────

@pytest.mark.asyncio
async def test_leak_report_by_invoice_id(admin_client, client, db_session):
    """POST /admin/proof-of-leak?invoice_id=... must create a valid evidence report."""
    invoice_id = f"LEAK-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=suspect_alice&is_paid=true"
    )
    # Create some activity to include in the report
    await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "secret-doc"},
    )

    res = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert res.status_code == 201
    body = res.json()

    assert body["resolution"]["invoice_id"] == invoice_id
    assert body["resolution"]["owner_id"] == "suspect_alice"
    assert body["resolution"]["method"] == "direct_invoice_id"
    assert "integrity_hash" in body
    assert body["integrity_hash"].startswith("sha256:")
    assert body["license"]["invoice_id"] == invoice_id
    assert len(body["viewing_sessions"]) >= 1
    assert body["viewing_sessions"][0]["content_id"] == "secret-doc"
    assert body["summary"]["total_sessions"] >= 1


# ── 2. Reverse lookup by watermark fingerprint ────────────────

@pytest.mark.asyncio
async def test_leak_report_by_fingerprint_reverse_lookup(admin_client, db_session):
    """POST /admin/proof-of-leak?fingerprint=N must resolve the owner via reverse lookup."""
    owner_id = f"suspect_{secrets.token_hex(4)}"
    invoice_id = f"LEAK-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id={owner_id}"
    )

    # Compute the same fingerprint the DRM system embeds in protected content
    fp = generate_user_fingerprint(owner_id)

    res = await admin_client.post(f"/admin/proof-of-leak?fingerprint={fp}")
    assert res.status_code == 201
    body = res.json()

    assert body["resolution"]["owner_id"] == owner_id
    assert body["resolution"]["invoice_id"] == invoice_id
    assert body["resolution"]["method"] == "fingerprint_match"
    assert body["resolution"]["fingerprint"] == str(fp)
    assert body["submitted_fingerprint"] == str(fp)


# ── 3. Unknown fingerprint → 404 ─────────────────────────────

@pytest.mark.asyncio
async def test_leak_report_unknown_fingerprint_returns_404(admin_client, db_session):
    """A fingerprint that matches no license must return 404."""
    res = await admin_client.post("/admin/proof-of-leak?fingerprint=9999999999")
    assert res.status_code == 404


# ── 4. Integrity hash is tamper-evident ──────────────────────

@pytest.mark.asyncio
async def test_leak_report_integrity_hash_matches_evidence(admin_client, db_session):
    """SHA-256 of the stored evidence_json must equal the returned integrity_hash."""
    invoice_id = f"HASH-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=hash_tester"
    )

    res = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert res.status_code == 201
    report_id = res.json()["report_id"]
    returned_hash = res.json()["integrity_hash"]

    # Retrieve the stored row and recompute the hash independently
    row = await db_session.get(models.LeakReport, report_id)
    assert row is not None

    expected_hash = "sha256:" + hashlib.sha256(row.evidence_json.encode()).hexdigest()
    assert row.integrity_hash == expected_hash, "Stored hash must match recomputed hash"
    assert returned_hash == expected_hash, "Returned hash must match stored hash"

    # Verify the evidence_json is valid JSON containing the report_id
    parsed = json.loads(row.evidence_json)
    assert parsed["report_id"] == report_id


# ── 5. Report is stored, listable, and retrievable by ID ─────

@pytest.mark.asyncio
async def test_leak_report_stored_listable_and_retrievable(admin_client, db_session):
    """GET /admin/proof-of-leak must list the report; GET /admin/proof-of-leak/{id} returns full evidence."""
    invoice_id = f"LIST-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=list_tester"
    )

    create_res = await admin_client.post(f"/admin/proof-of-leak?invoice_id={invoice_id}")
    assert create_res.status_code == 201
    report_id = create_res.json()["report_id"]

    # List endpoint must include this report
    list_res = await admin_client.get("/admin/proof-of-leak")
    assert list_res.status_code == 200
    reports = list_res.json()
    assert isinstance(reports, list)
    found = [r for r in reports if r["report_id"] == report_id]
    assert len(found) == 1
    assert found[0]["invoice_id"] == invoice_id

    # Detail endpoint must return the full evidence + integrity_hash
    get_res = await admin_client.get(f"/admin/proof-of-leak/{report_id}")
    assert get_res.status_code == 200
    detail = get_res.json()
    assert detail["report_id"] == report_id
    assert "integrity_hash" in detail
    assert "viewing_sessions" in detail
    assert "audit_trail" in detail
    assert "summary" in detail
