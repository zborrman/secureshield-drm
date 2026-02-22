"""
Reliability tests — Week 2 hardening.

Covers:
  1. Redis circuit breaker (CLOSED → OPEN → HALF-OPEN transitions + fallbacks)
  2. Stripe Webhook DLQ (idempotency, failure recording, admin list/retry)
"""
import json
import time
import pytest
from datetime import datetime
from unittest.mock import patch
from sqlalchemy.future import select

import redis_service
import models


# ── Helpers ───────────────────────────────────────────────────────────────────

def _open_circuit():
    """Force the circuit breaker into the OPEN state."""
    redis_service._circuit._failures = redis_service._circuit.FAILURE_THRESHOLD
    redis_service._circuit._opened_at = time.monotonic()


def _close_circuit():
    """Reset circuit breaker to CLOSED state."""
    redis_service._circuit._failures = 0
    redis_service._circuit._opened_at = None


def _make_stripe_event(event_id: str, invoice_id: str) -> dict:
    return {
        "id": event_id,
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "metadata": {"invoice_id": invoice_id},
            }
        },
    }


# ── Circuit breaker ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_circuit_opens_after_threshold(fake_redis):
    """Three consecutive record_failure() calls must open the circuit."""
    _close_circuit()
    assert not redis_service._circuit.is_open

    for _ in range(redis_service._circuit.FAILURE_THRESHOLD):
        redis_service._circuit.record_failure()

    assert redis_service._circuit.is_open
    _close_circuit()


@pytest.mark.asyncio
async def test_circuit_closes_on_success(fake_redis):
    """record_success() must reset failures and close an open circuit."""
    _open_circuit()
    assert redis_service._circuit.is_open

    redis_service._circuit.record_success()

    assert not redis_service._circuit.is_open
    assert redis_service._circuit._failures == 0


@pytest.mark.asyncio
async def test_is_revoked_returns_false_when_circuit_open(fake_redis):
    """is_revoked must return False (safe fallback) when circuit is open."""
    _open_circuit()
    result = await redis_service.is_revoked(session_id=999)
    assert result is False
    _close_circuit()


@pytest.mark.asyncio
async def test_register_session_noop_when_circuit_open(fake_redis):
    """register_session must be a no-op when the circuit is open."""
    _open_circuit()
    await redis_service.register_session(
        session_id=42,
        license_id=1,
        invoice_id="INV-CB",
        content_id="doc-cb",
        ip_address="1.2.3.4",
    )
    keys = [k async for k in fake_redis.scan_iter("session:*")]
    assert keys == [], "No Redis keys must be written when circuit is open"
    _close_circuit()


# ── Stripe DLQ ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_webhook_creates_dlq_entry(client, db_session):
    """A valid Stripe webhook must create a StripeWebhookEvent DLQ row."""
    event = _make_stripe_event("evt_dlq_create_001", "INV-DLQ-CREATE-01")

    with patch("stripe.Webhook.construct_event", return_value=event):
        res = await client.post(
            "/webhook/stripe",
            content=json.dumps(event).encode(),
            headers={"stripe-signature": "t=1,v1=dummy"},
        )
    assert res.status_code == 200

    row = await db_session.get(models.StripeWebhookEvent, "evt_dlq_create_001")
    assert row is not None
    assert row.event_type == "checkout.session.completed"
    assert row.status in ("processed", "failed")  # attempted


@pytest.mark.asyncio
async def test_webhook_idempotency(client, db_session):
    """Delivering the same Stripe event twice must result in only one DLQ row."""
    event = _make_stripe_event("evt_dlq_idem_001", "INV-DLQ-IDEM-01")

    with patch("stripe.Webhook.construct_event", return_value=event):
        r1 = await client.post(
            "/webhook/stripe",
            content=json.dumps(event).encode(),
            headers={"stripe-signature": "t=1,v1=dummy"},
        )
        r2 = await client.post(
            "/webhook/stripe",
            content=json.dumps(event).encode(),
            headers={"stripe-signature": "t=1,v1=dummy"},
        )

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_processed"

    # Exactly one row in the DB
    result = await db_session.execute(
        select(models.StripeWebhookEvent).where(
            models.StripeWebhookEvent.id == "evt_dlq_idem_001"
        )
    )
    rows = result.scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_invalid_stripe_signature_returns_400(client, db_session):
    """A webhook with a bad signature must return 400 and write no DLQ row."""
    res = await client.post(
        "/webhook/stripe",
        content=b'{"id":"evt_bad"}',
        headers={"stripe-signature": "t=1,v1=bad"},
    )
    assert res.status_code == 400

    row = await db_session.get(models.StripeWebhookEvent, "evt_bad")
    assert row is None


@pytest.mark.asyncio
async def test_admin_dlq_lists_events(admin_client, db_session):
    """GET /admin/stripe/dlq must return existing DLQ entries."""
    entry = models.StripeWebhookEvent(
        id="evt_dlq_list_001",
        event_type="checkout.session.completed",
        payload=json.dumps({"id": "evt_dlq_list_001"}),
        status="failed",
        error="transient db error",
        attempts=1,
    )
    db_session.add(entry)
    await db_session.commit()

    res = await admin_client.get("/admin/stripe/dlq")
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    matching = [e for e in events if e["id"] == "evt_dlq_list_001"]
    assert len(matching) == 1
    assert matching[0]["status"] == "failed"
    assert matching[0]["error"] == "transient db error"


@pytest.mark.asyncio
async def test_admin_dlq_filter_by_status(admin_client, db_session):
    """GET /admin/stripe/dlq?status=failed must return only failed events."""
    db_session.add(models.StripeWebhookEvent(
        id="evt_filter_proc",
        event_type="checkout.session.completed",
        payload="{}",
        status="processed",
    ))
    db_session.add(models.StripeWebhookEvent(
        id="evt_filter_fail",
        event_type="checkout.session.completed",
        payload="{}",
        status="failed",
        error="boom",
    ))
    await db_session.commit()

    res = await admin_client.get("/admin/stripe/dlq?status=failed")
    assert res.status_code == 200
    events = res.json()
    assert all(e["status"] == "failed" for e in events)


@pytest.mark.asyncio
async def test_admin_dlq_retry_processes_event(admin_client, db_session):
    """POST /admin/stripe/dlq/{id}/retry must reprocess a failed event."""
    invoice_id = "INV-DLQ-RETRY-01"

    # Create the license (unpaid)
    create_res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=retry_tester"
    )
    assert create_res.status_code == 201

    # Seed a failed DLQ entry
    event_payload = _make_stripe_event("evt_dlq_retry_001", invoice_id)
    entry = models.StripeWebhookEvent(
        id="evt_dlq_retry_001",
        event_type="checkout.session.completed",
        payload=json.dumps(event_payload),
        status="failed",
        error="transient error",
        attempts=1,
    )
    db_session.add(entry)
    await db_session.commit()

    # Retry the failed event
    res = await admin_client.post("/admin/stripe/dlq/evt_dlq_retry_001/retry")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "processed"
    assert body["attempts"] == 2

    # The license must now be marked paid
    lic_result = await db_session.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    assert lic is not None
    assert lic.is_paid is True


@pytest.mark.asyncio
async def test_admin_dlq_retry_already_processed_returns_409(admin_client, db_session):
    """POST /admin/stripe/dlq/{id}/retry on a processed event must return 409."""
    entry = models.StripeWebhookEvent(
        id="evt_dlq_done_001",
        event_type="checkout.session.completed",
        payload="{}",
        status="processed",
    )
    db_session.add(entry)
    await db_session.commit()

    res = await admin_client.post("/admin/stripe/dlq/evt_dlq_done_001/retry")
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_admin_dlq_retry_missing_event_returns_404(admin_client, db_session):
    """POST /admin/stripe/dlq/{id}/retry on a nonexistent event must return 404."""
    res = await admin_client.post("/admin/stripe/dlq/evt_nonexistent_999/retry")
    assert res.status_code == 404
