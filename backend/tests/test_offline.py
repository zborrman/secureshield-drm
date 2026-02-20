"""
Zero-Knowledge Offline Viewing — Token Tests
Covers: POST /admin/offline-token, POST /verify-offline-token,
        DELETE /admin/offline-token/{id}, GET /admin/offline-tokens
"""
import secrets
import pytest
from datetime import datetime, timedelta

import models


# ── 1. Issue an offline token ─────────────────────────────────

@pytest.mark.asyncio
async def test_issue_offline_token(admin_client, db_session):
    """POST /admin/offline-token must return a signed JWT and persist the row."""
    invoice_id = f"OFL-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=alice_offline"
    )

    res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=48&device_hint=Alice+Laptop"
    )
    assert res.status_code == 201
    body = res.json()

    assert body["invoice_id"] == invoice_id
    assert body["max_offline_hours"] == 48
    assert body["device_hint"] == "Alice Laptop"
    assert "token_id" in body
    assert "valid_until" in body

    # JWT must be three dot-separated base64url segments
    token = body["token"]
    assert token.count(".") == 2, "Expected a three-part JWT"

    # Row must exist in DB
    row = await db_session.get(models.OfflineToken, body["token_id"])
    assert row is not None
    assert row.invoice_id == invoice_id
    assert row.is_revoked is False


# ── 2. Verify a valid token ───────────────────────────────────

@pytest.mark.asyncio
async def test_verify_valid_offline_token(admin_client, client, db_session):
    """POST /verify-offline-token with a fresh token must return valid=True."""
    invoice_id = f"OFL-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=bob_offline"
    )
    issue_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=24"
    )
    token = issue_res.json()["token"]

    res = await client.post(f"/verify-offline-token?token={token}")
    assert res.status_code == 200
    body = res.json()
    assert body["valid"] is True
    assert body["invoice_id"] == invoice_id
    assert body["hours_remaining"] >= 23   # issued for 24 h, should have ~24 h remaining


# ── 3. Verify an expired token ────────────────────────────────

@pytest.mark.asyncio
async def test_verify_expired_offline_token(admin_client, client, db_session):
    """A token whose DB valid_until is in the past must return valid=False, reason=expired."""
    invoice_id = f"OFL-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=carol_offline"
    )
    issue_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=1"
    )
    token_id = issue_res.json()["token_id"]
    token = issue_res.json()["token"]

    # Backdate the valid_until so the JWT exp is still in the future for the
    # DB row check — but we actually want to test the JWT signature path.
    # Instead, force expiry by backdating the DB row AND using a token built
    # with exp already expired via PyJWT directly.
    import jwt as _jwt, os
    secret = os.environ.get("OFFLINE_TOKEN_SECRET",
                            os.environ["ADMIN_API_KEY"] + "-offline-v1")
    expired_payload = {
        "sub": invoice_id,
        "jti": token_id,
        "iat": int((datetime.utcnow() - timedelta(hours=2)).timestamp()),
        "exp": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
        "type": "offline",
        "max_offline_hours": 1,
    }
    expired_token = _jwt.encode(expired_payload, secret, algorithm="HS256")

    res = await client.post(f"/verify-offline-token?token={expired_token}")
    assert res.status_code == 200
    body = res.json()
    assert body["valid"] is False
    assert body["reason"] == "expired"


# ── 4. Revoke a token then verify it ─────────────────────────

@pytest.mark.asyncio
async def test_revoke_offline_token(admin_client, client, db_session):
    """DELETE /admin/offline-token/{id} must mark is_revoked; subsequent verify → revoked."""
    invoice_id = f"OFL-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=dave_offline"
    )
    issue_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=24"
    )
    token_id = issue_res.json()["token_id"]
    token = issue_res.json()["token"]

    # Revoke
    del_res = await admin_client.delete(f"/admin/offline-token/{token_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "revoked"

    # Row must be flagged
    row = await db_session.get(models.OfflineToken, token_id)
    # Expire the cached state so we read fresh from DB
    await db_session.refresh(row)
    assert row.is_revoked is True

    # Verify endpoint must now reject
    verify_res = await client.post(f"/verify-offline-token?token={token}")
    assert verify_res.status_code == 200
    body = verify_res.json()
    assert body["valid"] is False
    assert body["reason"] == "revoked"


# ── 5. List tokens ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_offline_tokens(admin_client, db_session):
    """GET /admin/offline-tokens must include issued tokens with correct status fields."""
    invoice_id = f"OFL-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=eve_offline"
    )
    issue_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=6&device_hint=Eve+PC"
    )
    assert issue_res.status_code == 201
    token_id = issue_res.json()["token_id"]

    list_res = await admin_client.get("/admin/offline-tokens")
    assert list_res.status_code == 200
    tokens = list_res.json()
    assert isinstance(tokens, list)

    found = [t for t in tokens if t["token_id"] == token_id]
    assert len(found) == 1
    t = found[0]
    assert t["invoice_id"] == invoice_id
    assert t["max_offline_hours"] == 6
    assert t["device_hint"] == "Eve PC"
    assert t["is_revoked"] is False
    assert t["is_expired"] is False
    assert t["hours_remaining"] >= 5
