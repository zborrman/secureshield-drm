"""
Week 6 — Bulk Import, Owner Email, Revocation Reason

Tests:
  1.  create-license stores owner_email
  2.  create-license with owner_email calls send_license_key (stub)
  3.  create-license without owner_email does NOT call send_license_key
  4.  email stub returns True when EMAIL_ENABLED=false (default)
  5.  email stub is a no-op when address is empty
  6.  bulk import: all valid rows created
  7.  bulk import: duplicate invoice_id recorded as conflict, not error
  8.  bulk import: row with missing owner_id recorded as error
  9.  bulk import: mixed CSV (valid + conflict + error) returns correct counts
  10. bulk import: max_sessions clamped to 1-100
  11. bulk import: is_paid parsed from "true" / "yes" / "1"
  12. revoke offline-token without reason — revocation_reason is None
  13. revoke offline-token with reason — stored and returned
  14. list offline-tokens includes revocation_reason field
"""
import io
import csv
import pytest
import secrets
from unittest.mock import AsyncMock, patch

import email_service


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_csv(*rows, header=("invoice_id", "owner_id", "max_sessions", "is_paid", "owner_email")) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow(row)
    return buf.getvalue().encode()


# ── 1. create-license stores owner_email ─────────────────────────────────────

@pytest.mark.asyncio
async def test_create_license_stores_owner_email(admin_client, db_session):
    from sqlalchemy.future import select
    import models

    invoice_id = f"EMAIL-{secrets.token_hex(4)}"
    res = await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=alice&owner_email=alice%40example.com"
    )
    assert res.status_code == 201

    result = await db_session.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    assert lic is not None
    assert lic.owner_email == "alice@example.com"


# ── 2. create-license calls send_license_key when email is set ───────────────

@pytest.mark.asyncio
async def test_create_license_calls_email_service(admin_client, db_session):
    invoice_id = f"EMAIL-{secrets.token_hex(4)}"
    with patch.object(email_service, "send_license_key", new=AsyncMock(return_value=True)) as mock_send:
        res = await admin_client.post(
            f"/admin/create-license?invoice_id={invoice_id}&owner_id=bob&owner_email=bob%40example.com"
        )
        assert res.status_code == 201
        mock_send.assert_awaited_once()
        call_kwargs = mock_send.call_args
        assert call_kwargs.args[0] == "bob@example.com"
        assert call_kwargs.args[1] == invoice_id


# ── 3. create-license without email does NOT call send_license_key ────────────

@pytest.mark.asyncio
async def test_create_license_no_email_skips_email_service(admin_client, db_session):
    invoice_id = f"NOEMAIL-{secrets.token_hex(4)}"
    with patch.object(email_service, "send_license_key", new=AsyncMock(return_value=True)) as mock_send:
        res = await admin_client.post(
            f"/admin/create-license?invoice_id={invoice_id}&owner_id=carol"
        )
        assert res.status_code == 201
        mock_send.assert_not_awaited()


# ── 4. email stub returns True when EMAIL_ENABLED=false ───────────────────────

@pytest.mark.asyncio
async def test_email_stub_returns_true_when_disabled():
    with patch.object(email_service, "EMAIL_ENABLED", False):
        result = await email_service.send_license_key(
            to="test@example.com", invoice_id="INV-001", plain_key="SK-abc"
        )
    assert result is True


# ── 5. email stub is no-op when address is empty ─────────────────────────────

@pytest.mark.asyncio
async def test_email_stub_noop_for_empty_address():
    with patch("email_service._send_sync") as mock_sync:
        result = await email_service.send_license_key(to="", invoice_id="INV-001", plain_key="SK-abc")
    assert result is True
    mock_sync.assert_not_called()


# ── 6. bulk import: all valid rows created ────────────────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_creates_all_valid_rows(admin_client, db_session):
    prefix = secrets.token_hex(3)
    csv_data = make_csv(
        (f"BULK-{prefix}-A", "alice", "1", "false", ""),
        (f"BULK-{prefix}-B", "bob",   "2", "true",  ""),
        (f"BULK-{prefix}-C", "carol", "1", "false", ""),
    )
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["created"] == 3
    assert body["conflict"] == 0
    assert body["failed"] == 0
    assert body["total"] == 3
    assert all(r["status"] == "created" for r in body["rows"])
    assert all(r["plain_key"] is not None for r in body["rows"])


# ── 7. bulk import: duplicate invoice_id → conflict ───────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_conflict_on_duplicate(admin_client, db_session):
    invoice_id = f"DUP-{secrets.token_hex(4)}"
    # Pre-create the license
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=dave"
    )
    csv_data = make_csv((invoice_id, "dave2", "1", "false", ""))
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["conflict"] == 1
    assert body["created"] == 0
    assert body["rows"][0]["status"] == "conflict"


# ── 8. bulk import: missing owner_id → error ──────────────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_error_on_missing_owner_id(admin_client, db_session):
    prefix = secrets.token_hex(3)
    csv_data = make_csv((f"MISSING-{prefix}", "", "1", "false", ""))
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["failed"] == 1
    assert body["rows"][0]["status"] == "error"


# ── 9. bulk import: mixed CSV returns correct counts ─────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_mixed_csv(admin_client, db_session):
    prefix = secrets.token_hex(3)
    dup_id = f"DUP2-{prefix}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={dup_id}&owner_id=existing"
    )
    csv_data = make_csv(
        (f"GOOD-{prefix}",    "alice",  "1", "false", ""),   # created
        (dup_id,              "bob",    "1", "false", ""),   # conflict
        ("",                  "carol",  "1", "false", ""),   # error (no invoice_id)
    )
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["created"]  == 1
    assert body["conflict"] == 1
    assert body["failed"]   == 1
    assert body["total"]    == 3


# ── 10. bulk import: max_sessions clamped ─────────────────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_clamps_max_sessions(admin_client, db_session):
    from sqlalchemy.future import select
    import models

    prefix = secrets.token_hex(3)
    invoice_id = f"CLAMP-{prefix}"
    csv_data = make_csv((invoice_id, "eve", "999", "false", ""))
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.status_code == 200
    assert res.json()["created"] == 1

    result = await db_session.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    assert lic.max_sessions == 100  # clamped from 999


# ── 11. bulk import: is_paid parsed correctly ─────────────────────────────────

@pytest.mark.asyncio
async def test_bulk_import_parses_is_paid(admin_client, db_session):
    from sqlalchemy.future import select
    import models

    prefix = secrets.token_hex(3)
    id_true  = f"PAID-T-{prefix}"
    id_yes   = f"PAID-Y-{prefix}"
    id_false = f"PAID-F-{prefix}"
    csv_data = make_csv(
        (id_true,  "a", "1", "true",  ""),
        (id_yes,   "b", "1", "yes",   ""),
        (id_false, "c", "1", "false", ""),
    )
    res = await admin_client.post(
        "/admin/licenses/bulk",
        files={"file": ("licenses.csv", csv_data, "text/csv")},
    )
    assert res.json()["created"] == 3

    for inv, expected_paid in [(id_true, True), (id_yes, True), (id_false, False)]:
        r = await db_session.execute(
            select(models.License).where(models.License.invoice_id == inv)
        )
        lic = r.scalars().first()
        assert lic.is_paid == expected_paid, f"{inv}: expected is_paid={expected_paid}"


# ── 12. revoke without reason — revocation_reason is None ────────────────────

@pytest.mark.asyncio
async def test_revoke_token_without_reason(admin_client, db_session):
    import models

    invoice_id = f"REV-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=frank&is_paid=true"
    )
    token_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=1"
    )
    token_id = token_res.json()["token_id"]

    del_res = await admin_client.delete(f"/admin/offline-token/{token_id}")
    assert del_res.status_code == 200
    body = del_res.json()
    assert body["status"] == "revoked"
    assert body["revocation_reason"] is None

    row = await db_session.get(models.OfflineToken, token_id)
    assert row.revocation_reason is None


# ── 13. revoke with reason — stored and returned ──────────────────────────────

@pytest.mark.asyncio
async def test_revoke_token_with_reason(admin_client, db_session):
    import models

    invoice_id = f"REV2-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=grace&is_paid=true"
    )
    token_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=1"
    )
    token_id = token_res.json()["token_id"]

    del_res = await admin_client.delete(
        f"/admin/offline-token/{token_id}?reason=lost_device"
    )
    assert del_res.status_code == 200
    body = del_res.json()
    assert body["revocation_reason"] == "lost_device"

    await db_session.refresh(await db_session.get(models.OfflineToken, token_id))
    row = await db_session.get(models.OfflineToken, token_id)
    assert row.revocation_reason == "lost_device"


# ── 14. list offline-tokens includes revocation_reason field ─────────────────

@pytest.mark.asyncio
async def test_list_offline_tokens_includes_revocation_reason(admin_client, db_session):
    invoice_id = f"LIST-{secrets.token_hex(4)}"
    await admin_client.post(
        f"/admin/create-license?invoice_id={invoice_id}&owner_id=henry&is_paid=true"
    )
    token_res = await admin_client.post(
        f"/admin/offline-token?invoice_id={invoice_id}&hours=1"
    )
    token_id = token_res.json()["token_id"]
    await admin_client.delete(f"/admin/offline-token/{token_id}?reason=theft")

    list_res = await admin_client.get("/admin/offline-tokens")
    assert list_res.status_code == 200
    tokens = list_res.json()
    match = next((t for t in tokens if t["token_id"] == token_id), None)
    assert match is not None
    assert "revocation_reason" in match
    assert match["revocation_reason"] == "theft"
