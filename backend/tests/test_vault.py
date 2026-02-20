"""
Content Vault tests.

All tests use the `mock_s3` fixture (defined in conftest.py) which:
  - activates moto's in-process S3 mock
  - creates the test bucket
  - resets vault_service._s3 before/after for a fresh boto3 client
"""
import io
import pytest
import pytest_asyncio


# ── Helpers ───────────────────────────────────────────────────────────────────

ADMIN_KEY = "test-admin-key"
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_KEY}

SAMPLE_CONTENT = b"Hello, Vault! This is protected content."
SAMPLE_FILENAME = "test-doc.txt"


def _upload_file(content: bytes = SAMPLE_CONTENT, filename: str = SAMPLE_FILENAME):
    """Return kwargs for httpx multipart file upload."""
    return {"files": {"file": (filename, io.BytesIO(content), "text/plain")}}


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upload_stores_encrypted_content(db_session, admin_client, mock_s3):
    """POST /admin/vault/upload → 201; content stored in S3 (encrypted) and DB."""
    resp = await admin_client.post(
        "/admin/vault/upload?description=My+Test+Doc",
        **_upload_file(),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["filename"] == SAMPLE_FILENAME
    assert data["size_bytes"] == len(SAMPLE_CONTENT)
    assert "content_id" in data

    # Confirm DB row was created and key is not plaintext
    import models
    from sqlalchemy.future import select
    row = await db_session.get(models.VaultContent, data["content_id"])
    assert row is not None
    assert row.encrypted_key != SAMPLE_CONTENT.decode(errors="replace")
    assert row.iv  # AES-GCM nonce must be present


@pytest.mark.asyncio
async def test_admin_list_returns_uploaded_items(db_session, admin_client, mock_s3):
    """GET /admin/vault/contents → lists all uploaded items."""
    # Upload two files
    await admin_client.post("/admin/vault/upload", **_upload_file(b"file-1", "a.txt"))
    await admin_client.post("/admin/vault/upload", **_upload_file(b"file-2", "b.txt"))

    resp = await admin_client.get("/admin/vault/contents")
    assert resp.status_code == 200
    items = resp.json()
    filenames = [i["filename"] for i in items]
    assert "a.txt" in filenames
    assert "b.txt" in filenames
    # Sensitive fields must NOT appear in the listing
    for item in items:
        assert "encrypted_key" not in item
        assert "s3_key" not in item
        assert "iv" not in item


@pytest.mark.asyncio
async def test_vault_access_and_stream(db_session, admin_client, client, mock_s3):
    """POST /vault/access/{id} → JWT; GET /vault/stream/{jwt} → decrypted bytes."""
    # 1. Upload
    up = await admin_client.post("/admin/vault/upload", **_upload_file())
    assert up.status_code == 201
    content_id = up.json()["content_id"]

    # 2. Create a paid license
    lic = await admin_client.post(
        "/admin/create-license?invoice_id=inv-vault-1&owner_id=alice&max_sessions=3"
    )
    assert lic.status_code == 201
    plain_key = lic.json()["plain_key_to_copy"]

    # 3. Get access token
    access_resp = await client.post(
        f"/vault/access/{content_id}",
        params={"invoice_id": "inv-vault-1", "license_key": plain_key},
    )
    assert access_resp.status_code == 200, access_resp.text
    access_token = access_resp.json()["access_token"]
    assert access_token

    # 4. Stream and verify decrypted content matches original
    stream_resp = await client.get(f"/vault/stream/{access_token}")
    assert stream_resp.status_code == 200, f"stream error ({stream_resp.status_code}): {stream_resp.text}"
    assert stream_resp.content == SAMPLE_CONTENT


@pytest.mark.asyncio
async def test_stream_rejects_expired_token(db_session, admin_client, client, mock_s3):
    """GET /vault/stream with an expired JWT → 401."""
    import jwt as _jwt
    import os
    from datetime import datetime, timedelta

    # Manually forge an already-expired token
    secret = os.getenv("OFFLINE_TOKEN_SECRET", os.getenv("ADMIN_API_KEY", "") + "-offline-v1")
    expired_token = _jwt.encode(
        {
            "type": "vault_access",
            "sub": "some-content-id",
            "session_id": 99,
            "iat": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
            "exp": int((datetime.utcnow() - timedelta(seconds=1)).timestamp()),
        },
        secret,
        algorithm="HS256",
    )
    resp = await client.get(f"/vault/stream/{expired_token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_removes_content(db_session, admin_client, mock_s3):
    """DELETE /admin/vault/{id} → 200; subsequent list no longer includes item."""
    # Upload
    up = await admin_client.post("/admin/vault/upload", **_upload_file())
    assert up.status_code == 201
    content_id = up.json()["content_id"]

    # Delete
    del_resp = await admin_client.delete(f"/admin/vault/{content_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    # List should be empty
    list_resp = await admin_client.get("/admin/vault/contents")
    assert list_resp.status_code == 200
    ids = [i["content_id"] for i in list_resp.json()]
    assert content_id not in ids
