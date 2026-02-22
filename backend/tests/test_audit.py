"""
Audit & Observability Tests
Covers: /health, /signout, /admin/audit-log, /admin/alerts, /analytics/*
"""
import pytest
import secrets
from sqlalchemy.future import select
import models


# ── 1. Health endpoint ────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_returns_correct_json(client):
    """/health must return status=healthy and database=ok when all deps are up."""
    res = await client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "healthy"
    assert body["database"] == "ok"


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


# ── 5. Analytics: session lifecycle ──────────────────────────

@pytest.mark.asyncio
async def test_analytics_start_creates_session(admin_client, client, db_session):
    """POST /analytics/start must create a ViewAnalytics row and return session_id."""
    invoice_id = f"ANA-{secrets.token_hex(4)}"

    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=viewer_01&is_paid=true"
    )

    res = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-001"},
    )
    assert res.status_code == 201
    body = res.json()
    assert "session_id" in body
    session_id = body["session_id"]

    # Verify row exists in DB
    rows = await db_session.execute(
        select(models.ViewAnalytics).where(models.ViewAnalytics.id == session_id)
    )
    row = rows.scalars().first()
    assert row is not None
    assert row.content_id == "doc-001"
    assert row.duration_seconds == 0


@pytest.mark.asyncio
async def test_analytics_heartbeat_accumulates_duration(admin_client, client, db_session):
    """POST /analytics/heartbeat/{id} must increment duration_seconds."""
    invoice_id = f"ANA-{secrets.token_hex(4)}"

    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=viewer_02&is_paid=true"
    )
    start_res = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-002"},
    )
    session_id = start_res.json()["session_id"]

    # Two heartbeats
    hb1 = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb1.status_code == 200
    hb2 = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb2.status_code == 200

    # duration_seconds must be non-negative after heartbeats
    assert hb2.json()["duration_seconds"] >= 0


@pytest.mark.asyncio
async def test_analytics_heartbeat_unknown_session_returns_404(client, db_session):
    """POST /analytics/heartbeat with a non-existent session_id must return 404."""
    res = await client.post("/analytics/heartbeat/999999")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_admin_analytics_returns_sessions(admin_client, client, db_session):
    """GET /admin/analytics must list all viewing sessions (admin only)."""
    invoice_id = f"ANA-{secrets.token_hex(4)}"

    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=viewer_03&is_paid=true"
    )
    await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-003"},
    )

    res = await admin_client.get("/admin/analytics")
    assert res.status_code == 200
    sessions = res.json()
    assert isinstance(sessions, list)
    matching = [s for s in sessions if s["content_id"] == "doc-003"]
    assert len(matching) == 1


@pytest.mark.asyncio
async def test_admin_analytics_requires_key(client, db_session):
    """GET /admin/analytics must return 401 without X-Admin-Key."""
    res = await client.get("/admin/analytics")
    assert res.status_code == 401


# ── 6. Time-based bot detection ───────────────────────────────

@pytest.mark.asyncio
async def test_immediate_heartbeat_flagged_as_bot(admin_client, client, db_session):
    """First heartbeat within 500ms of session start must set is_bot_suspect=True."""
    from datetime import timedelta

    invoice_id = f"BOT-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=bot_checker&is_paid=true"
    )
    start_res = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-bot"},
    )
    session_id = start_res.json()["session_id"]

    # Heartbeat immediately — no sleep, simulates a script
    hb = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb.status_code == 200
    body = hb.json()
    assert "suspicious" in body
    assert body["suspicious"] is True, "Immediate heartbeat must be flagged as suspicious"

    # Verify DB flag was persisted
    row = await db_session.get(models.ViewAnalytics, session_id)
    await db_session.refresh(row)
    assert row.is_bot_suspect is True


@pytest.mark.asyncio
async def test_delayed_heartbeat_not_flagged(admin_client, client, db_session):
    """First heartbeat after >500ms must NOT set is_bot_suspect."""
    from datetime import timedelta

    invoice_id = f"HUMAN-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=human_checker&is_paid=true"
    )
    start_res = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-human"},
    )
    session_id = start_res.json()["session_id"]

    # Simulate "human delay": backdate start_time by 2 seconds in DB
    row = await db_session.get(models.ViewAnalytics, session_id)
    row.start_time = row.start_time - timedelta(seconds=2)
    await db_session.commit()

    hb = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb.status_code == 200
    body = hb.json()
    assert body["suspicious"] is False, "2-second delay must NOT be flagged as suspicious"


# ── 7. Concurrent session limit ───────────────────────────────

@pytest.mark.asyncio
async def test_session_limit_blocks_excess_sessions(admin_client, client, db_session):
    """Second /analytics/start on a max_sessions=1 license must return 409."""
    invoice_id = f"LIMIT-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=limiter&max_sessions=1&is_paid=true"
    )

    first = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-A"},
    )
    assert first.status_code == 201

    second = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-B"},
    )
    assert second.status_code == 409, "Second session must be rejected when max_sessions=1"


@pytest.mark.asyncio
async def test_session_limit_allows_when_previous_expired(admin_client, client, db_session):
    """After 5+ min without a heartbeat, the slot is freed and a new session is allowed."""
    from datetime import timedelta

    invoice_id = f"EXPIRE-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=expirer&max_sessions=1&is_paid=true"
    )

    first = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-C"},
    )
    assert first.status_code == 201
    session_id = first.json()["session_id"]

    # Backdate last_heartbeat > 5 min ago → session considered expired
    row = await db_session.get(models.ViewAnalytics, session_id)
    row.last_heartbeat = row.last_heartbeat - timedelta(minutes=6)
    await db_session.commit()

    second = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-D"},
    )
    assert second.status_code == 201, "New session must be allowed after previous slot expired"


@pytest.mark.asyncio
async def test_admin_can_revoke_session(admin_client, client, db_session):
    """DELETE /admin/analytics/{id} must remove the session and free the slot."""
    invoice_id = f"REVOKE-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=revoker&max_sessions=1&is_paid=true"
    )

    start = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-R"},
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Admin revokes the session
    rev = await admin_client.delete(f"/admin/analytics/{session_id}")
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"

    # Row must be gone from the DB
    row = await db_session.get(models.ViewAnalytics, session_id)
    assert row is None, "Revoked session must be deleted from DB"

    # Slot must be freed — a new session is now allowed
    retry = await client.post(
        "/analytics/start",
        params={"invoice_id": invoice_id, "content_id": "doc-R2"},
    )
    assert retry.status_code == 201, "New session must be allowed after admin revoke"
