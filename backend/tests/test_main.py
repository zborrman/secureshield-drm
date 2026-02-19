import pytest
from httpx import AsyncClient
from main import app
import secrets

@pytest.mark.asyncio
async def test_security_workflow(admin_client, client, db_session):
    # 1. SETUP: Create a test license
    invoice_id = f"TEST-{secrets.token_hex(4)}"
    admin_res = await admin_client.post(f"/admin/create-license?invoice_id={invoice_id}&owner_id=tester_01")
    assert admin_res.status_code == 201
    plain_key = admin_res.json()["plain_key_to_copy"]

    # 2. VALIDATION: Check that the key is NOT stored in plaintext
    from models import License
    from sqlalchemy import select
    res = await db_session.execute(select(License).where(License.invoice_id == invoice_id))
    db_record = res.scalars().first()
    assert db_record is not None
    assert db_record.license_key != plain_key  # Must be hashed!

    # 3. ERROR CHECK: Verify with WRONG key
    wrong_res = await client.post("/verify-license", params={"invoice_id": invoice_id, "input_key": "wrong_key"})
    assert wrong_res.status_code == 403

    # 4. SUCCESS CHECK: Verify with CORRECT key after "payment"
    db_record.is_paid = True
    await db_session.commit()

    success_res = await client.post("/verify-license", params={"invoice_id": invoice_id, "input_key": plain_key})
    assert success_res.status_code == 200
    assert "fingerprint" in success_res.json()
