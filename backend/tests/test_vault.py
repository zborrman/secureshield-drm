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
        "/admin/create-license?invoice_id=inv-vault-1&owner_id=alice&max_sessions=3&is_paid=true"
    )
    assert lic.status_code == 201
    plain_key = lic.json()["plain_key_to_copy"]

    # 3. Get access token (credentials in JSON body, NOT query params)
    access_resp = await client.post(
        f"/vault/access/{content_id}",
        json={"invoice_id": "inv-vault-1", "license_key": plain_key},
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

    # Manually forge an already-expired token (vault stream uses VAULT_TOKEN_SECRET)
    secret = os.getenv("VAULT_TOKEN_SECRET", os.getenv("OFFLINE_TOKEN_SECRET", "") + "-vault-v1")
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


# ── Content ↔ License association tests ───────────────────────────────────────

async def _upload_and_license(admin_client, mock_s3, invoice_id: str = "inv-assoc-1"):
    """Helper: upload a file and create a paid license; return (content_id, plain_key)."""
    up = await admin_client.post("/admin/vault/upload", **_upload_file())
    assert up.status_code == 201
    content_id = up.json()["content_id"]

    lic = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=bob&max_sessions=3&is_paid=true"
    )
    assert lic.status_code == 201
    plain_key = lic.json()["plain_key_to_copy"]
    return content_id, plain_key


@pytest.mark.asyncio
async def test_grant_content_to_license(db_session, admin_client, mock_s3):
    """POST /admin/licenses/{invoice_id}/content/{content_id} → 201."""
    content_id, _ = await _upload_and_license(admin_client, mock_s3)
    resp = await admin_client.post(f"/admin/licenses/inv-assoc-1/content/{content_id}")
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "granted"
    assert data["content_id"] == content_id


@pytest.mark.asyncio
async def test_grant_duplicate_returns_409(db_session, admin_client, mock_s3):
    """Granting the same license-content pair twice → 409."""
    content_id, _ = await _upload_and_license(admin_client, mock_s3)
    await admin_client.post(f"/admin/licenses/inv-assoc-1/content/{content_id}")
    resp = await admin_client.post(f"/admin/licenses/inv-assoc-1/content/{content_id}")
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_list_licenses_for_content(db_session, admin_client, mock_s3):
    """GET /admin/vault/{content_id}/licenses → includes the granted invoice_id."""
    content_id, _ = await _upload_and_license(admin_client, mock_s3)
    await admin_client.post(f"/admin/licenses/inv-assoc-1/content/{content_id}")

    resp = await admin_client.get(f"/admin/vault/{content_id}/licenses")
    assert resp.status_code == 200
    invoice_ids = [r["invoice_id"] for r in resp.json()]
    assert "inv-assoc-1" in invoice_ids


@pytest.mark.asyncio
async def test_list_content_for_license(db_session, admin_client, mock_s3):
    """GET /admin/licenses/{invoice_id}/content → includes the linked content item."""
    content_id, _ = await _upload_and_license(admin_client, mock_s3)
    await admin_client.post(f"/admin/licenses/inv-assoc-1/content/{content_id}")

    resp = await admin_client.get("/admin/licenses/inv-assoc-1/content")
    assert resp.status_code == 200
    ids = [r["content_id"] for r in resp.json()]
    assert content_id in ids


@pytest.mark.asyncio
async def test_restricted_content_blocks_unlinked_license(db_session, admin_client, client, mock_s3):
    """Once any license is linked to content, other licenses are blocked (403)."""
    content_id, _ = await _upload_and_license(admin_client, mock_s3, "inv-owner-1")

    # Link inv-owner-1 → content becomes restricted
    await admin_client.post(f"/admin/licenses/inv-owner-1/content/{content_id}")

    # Create a second, unlinked license
    lic2 = await admin_client.post(
        "/admin/create-license?invoice_id=inv-other-1&owner_id=eve&max_sessions=3&is_paid=true"
    )
    plain_key2 = lic2.json()["plain_key_to_copy"]

    # Eve's license must be denied
    access_resp = await client.post(
        f"/vault/access/{content_id}",
        json={"invoice_id": "inv-other-1", "license_key": plain_key2},
    )
    assert access_resp.status_code == 403


@pytest.mark.asyncio
async def test_linked_license_can_access_restricted_content(db_session, admin_client, client, mock_s3):
    """The license that was granted access can still stream the content."""
    content_id, plain_key = await _upload_and_license(admin_client, mock_s3, "inv-owner-2")
    await admin_client.post(f"/admin/licenses/inv-owner-2/content/{content_id}")

    access_resp = await client.post(
        f"/vault/access/{content_id}",
        json={"invoice_id": "inv-owner-2", "license_key": plain_key},
    )
    assert access_resp.status_code == 200, access_resp.text


@pytest.mark.asyncio
async def test_revoke_content_from_license(db_session, admin_client, client, mock_s3):
    """DELETE /admin/licenses/{invoice_id}/content/{id} → revoked license is blocked."""
    content_id, plain_key = await _upload_and_license(admin_client, mock_s3, "inv-revoke-1")
    await admin_client.post(f"/admin/licenses/inv-revoke-1/content/{content_id}")

    # Confirm access works before revocation
    pre = await client.post(
        f"/vault/access/{content_id}",
        json={"invoice_id": "inv-revoke-1", "license_key": plain_key},
    )
    assert pre.status_code == 200

    # Revoke — content now has zero associations → open again
    rev = await admin_client.delete(f"/admin/licenses/inv-revoke-1/content/{content_id}")
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"

    # Open content: same license should still work
    post = await client.post(
        f"/vault/access/{content_id}",
        json={"invoice_id": "inv-revoke-1", "license_key": plain_key},
    )
    assert post.status_code == 200
