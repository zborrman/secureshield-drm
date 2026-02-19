import pytest
from sqlalchemy.future import select
import models

@pytest.mark.asyncio
async def test_full_license_lifecycle(admin_client, client, db_session):
    # 1. ADMIN: Создаем лицензию
    invoice_id = "TEST-INV-001"
    create_res = await admin_client.post(f"/admin/create-license?invoice_id={invoice_id}&owner_id=tester")
    assert create_res.status_code == 201
    plain_key = create_res.json()["plain_key_to_copy"]

    # 2. STRIPE: Имитируем оплату через вебхук
    # (В реальности мы бы добавили проверку подписи Stripe, в тестах мокаем событие)
    webhook_payload = {
        "type": "checkout.session.completed",
        "data": {"object": {"metadata": {"invoice_id": invoice_id}}}
    }
    # Для теста временно отключаем проверку подписи или тестируем внутренний сервис
    from stripe_service import handle_payment_success
    await handle_payment_success(invoice_id)

    # 3. USER: Проверяем верный ключ
    verify_res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": plain_key}
    )
    assert verify_res.status_code == 200
    assert "fingerprint" in verify_res.json()

    # 4. AUDIT: Проверяем, что в логах появилась запись об успехе
    logs = await db_session.execute(select(models.AuditLog).where(models.AuditLog.invoice_id == invoice_id))
    log_entry = logs.scalars().first()
    assert log_entry is not None
    assert log_entry.is_success == True

@pytest.mark.asyncio
async def test_brute_force_protection(admin_client, client, db_session):
    invoice_id = "BRUTE-TEST"
    # Создаем лицензию, но не платим
    await admin_client.post(f"/admin/create-license?invoice_id={invoice_id}&owner_id=hacker")

    # 5 неудачных попыток
    for _ in range(5):
        res = await client.post(
            "/verify-license",
            params={"invoice_id": invoice_id, "input_key": "WRONG_KEY"}
        )
        assert res.status_code == 403

    # 6-я попытка должна вернуть 429 (Rate Limit)
    final_res = await client.post(
        "/verify-license",
        params={"invoice_id": invoice_id, "input_key": "WRONG_KEY"}
    )
    assert final_res.status_code == 429
    assert "IP временно заблокирован" in final_res.json()["detail"]
