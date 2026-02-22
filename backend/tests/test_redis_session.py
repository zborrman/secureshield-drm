"""
Session Orchestration & Real-time Revocation — Redis Tests
Covers:
  POST /analytics/start      (registers in Redis)
  POST /analytics/heartbeat  (revocation fast-path, TTL refresh)
  DELETE /admin/analytics/id (Redis revocation + Pub/Sub publish)
  GET  /admin/sessions/live  (real-time from Redis)
  POST /admin/sessions/revoke-all/{invoice_id}  (bulk revocation)
"""
import json
import secrets
import pytest

import redis_service


# ── helpers ───────────────────────────────────────────────────────────────────

async def _create_license(admin_client, invoice_id: str, owner_id: str = "tester"):
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id={owner_id}&is_paid=true"
    )
    assert res.status_code == 201
    return res.json()


async def _start_session(client, invoice_id: str, content_id: str = "vid-1"):
    res = await client.post(
        f"/analytics/start?invoice_id={invoice_id}&content_id={content_id}"
    )
    assert res.status_code == 201
    return res.json()["session_id"]


# ── 1. Session is registered in Redis on /analytics/start ─────────────────────

@pytest.mark.asyncio
async def test_session_registered_in_redis_on_start(
    admin_client, client, db_session, fake_redis
):
    """After /analytics/start, the session key must exist in Redis."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id)
    session_id = await _start_session(client, invoice_id)

    raw = await fake_redis.get(redis_service._session_key(session_id))
    assert raw is not None, "session key must be written to Redis"
    data = json.loads(raw)
    assert data["session_id"] == session_id
    assert data["invoice_id"] == invoice_id

    # Also registered in the license set
    members = await fake_redis.smembers(
        redis_service._license_sessions_key(data["license_id"])
    )
    assert str(session_id) in members


# ── 2. Heartbeat refreshes the Redis TTL ──────────────────────────────────────

@pytest.mark.asyncio
async def test_heartbeat_refreshes_redis_ttl(
    admin_client, client, db_session, fake_redis
):
    """POST /analytics/heartbeat must reset the session key TTL to SESSION_TTL_S."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id)
    session_id = await _start_session(client, invoice_id)

    # Manually set a very short TTL to simulate near-expiry
    await fake_redis.expire(redis_service._session_key(session_id), 5)
    ttl_before = await fake_redis.ttl(redis_service._session_key(session_id))
    assert ttl_before <= 5

    # Send a heartbeat
    hb_res = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb_res.status_code == 200
    assert hb_res.json().get("revoked") is False

    # TTL should be back to full SESSION_TTL_S
    ttl_after = await fake_redis.ttl(redis_service._session_key(session_id))
    assert ttl_after > 5, "TTL should have been refreshed after heartbeat"


# ── 3. Heartbeat returns revoked=True after admin revokes session ──────────────

@pytest.mark.asyncio
async def test_heartbeat_returns_revoked_after_admin_delete(
    admin_client, client, db_session, fake_redis
):
    """DELETE /admin/analytics/{id} must set the Redis revocation flag;
    the next heartbeat must return {"revoked": true, "action": "stop"}."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id)
    session_id = await _start_session(client, invoice_id)

    # Admin revokes
    del_res = await admin_client.delete(f"/admin/analytics/{session_id}")
    assert del_res.status_code == 200

    # Redis revocation flag must be set
    assert await fake_redis.exists(redis_service._revoked_key(session_id))

    # Next heartbeat must signal the viewer to stop
    hb_res = await client.post(f"/analytics/heartbeat/{session_id}")
    assert hb_res.status_code == 200
    body = hb_res.json()
    assert body.get("revoked") is True
    assert body.get("action") == "stop"


# ── 4. Live sessions endpoint reads from Redis ────────────────────────────────

@pytest.mark.asyncio
async def test_live_sessions_endpoint_reflects_redis(
    admin_client, client, db_session, fake_redis
):
    """GET /admin/sessions/live must return sessions registered in Redis."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id)
    session_id = await _start_session(client, invoice_id, content_id="doc-alpha")

    res = await admin_client.get("/admin/sessions/live")
    assert res.status_code == 200
    sessions = res.json()
    assert isinstance(sessions, list)
    found = [s for s in sessions if s["session_id"] == session_id]
    assert len(found) == 1
    assert found[0]["invoice_id"] == invoice_id
    assert found[0]["content_id"] == "doc-alpha"


# ── 5. Revoke-all instantly flags every session for a license ─────────────────

@pytest.mark.asyncio
async def test_revoke_all_sessions_for_license(
    admin_client, client, db_session, fake_redis
):
    """POST /admin/sessions/revoke-all/{invoice_id} must set revocation flags
    for all active sessions; subsequent heartbeats must all return revoked=True."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id, owner_id="bulk_victim")

    # Allow 3 concurrent sessions for this test
    await admin_client.patch(f"/admin/licenses/{invoice_id}/geo")  # no-op geo
    # Bump max_sessions to 3 via a fresh license (simpler: directly update DB row)
    from sqlalchemy.future import select
    import models
    lic = (
        await db_session.execute(
            select(models.License).where(models.License.invoice_id == invoice_id)
        )
    ).scalars().first()
    lic.max_sessions = 3
    await db_session.commit()

    # Open 3 sessions
    ids = [await _start_session(client, invoice_id, f"content-{i}") for i in range(3)]

    # Bulk revoke
    rv_res = await admin_client.post(f"/admin/sessions/revoke-all/{invoice_id}")
    assert rv_res.status_code == 200
    body = rv_res.json()
    assert body["revoked_count"] >= 3

    # Every session must report revoked on next heartbeat
    for sid in ids:
        hb = await client.post(f"/analytics/heartbeat/{sid}")
        assert hb.json().get("revoked") is True, f"session {sid} should be revoked"


# ── 6. Redis Pub/Sub event is published on revocation ─────────────────────────

@pytest.mark.asyncio
async def test_revocation_publishes_redis_event(
    admin_client, client, db_session, fake_redis
):
    """Revoking a session must publish a JSON message to drm:revocations channel."""
    invoice_id = f"RS-{secrets.token_hex(4)}"
    await _create_license(admin_client, invoice_id)
    session_id = await _start_session(client, invoice_id)

    # Subscribe before the revocation so we can catch the message
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(redis_service.REVOCATION_CHANNEL)
    # Flush the subscribe-confirmation message
    await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)

    # Revoke
    await admin_client.delete(f"/admin/analytics/{session_id}")

    # There should now be a message in the channel
    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
    assert msg is not None, "Expected a Pub/Sub message after revocation"
    event = json.loads(msg["data"])
    assert event["session_id"] == session_id
    assert event["action"] == "revoked"
    assert event["invoice_id"] == invoice_id

    await pubsub.aclose()
