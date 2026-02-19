"""
Audit & Observability Tests
Covers: /health, /signout, /admin/audit-log, /admin/alerts
"""
import pytest
import secrets
from sqlalchemy.future import select
import models


# ── 1. Health endpoint ────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_returns_correct_json(client):
    """/health must return {"status": "healthy", "database": "connected"}."""
    res = await client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "healthy"
    assert body["database"] == "connected"


# ── 2. Signout audit logging ──────────────────────────────────

@pytest.mark.asyncio
async def test_signout_creates_audit_entry(admin_client, client, db_session):
    """POST /signout must write an AuditLog row tagged with 'SIGNOUT'."""
    invoice_id = f"SIGNOUT-{secrets.token_hex(4)}"

    # Create a license first (so the invoice_id is known to the system)
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=logout_tester"
    )

    res = await client.post(
        "/signout",
        params={"invoice_id": invoice_id},
        headers={"user-agent": "TestBrowser/1.0"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "signed_out"

    # Verify the audit row was written
    rows = await db_session.execute(
        select(models.AuditLog).where(models.AuditLog.invoice_id == invoice_id)
    )
    entry = rows.scalars().first()
    assert entry is not None, "Signout must create an AuditLog row"
    assert "SIGNOUT" in entry.user_agent, "Signout row must be tagged SIGNOUT in user_agent"
    assert entry.is_success == False  # Signout is logged as a non-success event


# ── 3. Admin audit-log contains all events ───────────────────

@pytest.mark.asyncio
async def test_admin_audit_log_records_verify_attempts(admin_client, client, db_session):
    """GET /admin/audit-log must return rows that include failed verify attempts."""
    invoice_id = f"AUDIT-{secrets.token_hex(4)}"

    # Create license, make a failed verify attempt
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=audit_tester"
    )
    await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": "bad_key"},
    )

    # Fetch audit log via admin endpoint
    log_res = await admin_client.get("/admin/audit-log")
    assert log_res.status_code == 200
    entries = log_res.json()
    assert isinstance(entries, list), "audit-log must return a list"
    assert len(entries) >= 1, "At least one audit entry expected after a failed verify"

    # At least one entry must match our invoice
    invoice_entries = [e for e in entries if e["invoice_id"] == invoice_id]
    assert len(invoice_entries) >= 1, f"No audit entry found for {invoice_id}"
    assert invoice_entries[0]["is_success"] == False


# ── 4. Admin alerts detects recent failures ───────────────────

@pytest.mark.asyncio
async def test_admin_alerts_shows_recent_failures(admin_client, client, db_session):
    """GET /admin/alerts must include failed attempts from the last 30 minutes."""
    invoice_id = f"ALERT-{secrets.token_hex(4)}"

    # Create license, generate 2 failed attempts
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=alert_tester"
    )
    for _ in range(2):
        await client.post(
            "/verify-license",
            params={"invoice_id": invoice_id, "input_key": "wrong"},
        )

    alerts_res = await admin_client.get("/admin/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert isinstance(alerts, list), "alerts must return a list"

    # Our recent failures must appear
    matching = [a for a in alerts if a["invoice_id"] == invoice_id]
    assert len(matching) == 2, (
        f"Expected 2 alerts for {invoice_id}, got {len(matching)}"
    )
    for alert in matching:
        assert alert["is_success"] == False
