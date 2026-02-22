"""
Full lifecycle and brute-force tests.

Moved from backend/test_security.py (which was outside the tests/ directory
and therefore not collected by pytest).  Tests are isolated via db_session
so they do not interfere with each other or leave stale data.
"""
import secrets
import pytest
from sqlalchemy.future import select
import models
from stripe_service import handle_payment_success


# ── 1. Full license lifecycle ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_license_lifecycle(admin_client, client, db_session):
    """Admin creates license → Stripe pays → user verifies → audit log recorded."""
    invoice_id = f"LIFECYCLE-{secrets.token_hex(4)}"

    # 1. Admin creates the license
    create_res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=tester"
    )
    assert create_res.status_code == 201
    plain_key = create_res.json()["plain_key_to_copy"]

    # 2. Simulate Stripe payment success via the internal service
    await handle_payment_success(invoice_id)

    # 3. User verifies the correct key
    verify_res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key},
    )
    assert verify_res.status_code == 200
    assert "fingerprint" in verify_res.json()

    # 4. Audit log must contain a successful entry for this invoice
    logs = await db_session.execute(
        select(models.AuditLog).where(
            models.AuditLog.invoice_id == invoice_id,
            models.AuditLog.is_success == True,
        )
    )
    log_entry = logs.scalars().first()
    assert log_entry is not None, "Successful verification must be recorded in audit log"


# ── 2. Brute-force protection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_brute_force_protection(admin_client, client, db_session):
    """After 5 failed attempts the 6th must return 429 Too Many Requests."""
    invoice_id = f"BRUTE-{secrets.token_hex(4)}"

    # Create a license (unpaid — but we only care about failed attempts)
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=hacker"
    )

    # 5 failed attempts — all must return 403
    for _ in range(5):
        res = await client.post(
            "/verify-license",
            params={"invoice_id": invoice_id, "input_key": "WRONG_KEY"},
        )
        assert res.status_code == 403

    # 6th attempt from the same IP must be rate-limited
    final_res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": "WRONG_KEY"},
    )
    assert final_res.status_code == 429
    assert "Too many failed attempts" in final_res.json()["detail"]
