import stripe
import os
from database import SessionLocal
import models
from sqlalchemy.future import select

stripe.api_key = os.getenv("STRIPE_API_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

async def handle_payment_success(invoice_id: str):
    """Обновляет статус лицензии в БД при успешной оплате."""
    async with SessionLocal() as db:
        result = await db.execute(select(models.License).where(models.License.invoice_id == invoice_id))
        license_record = result.scalars().first()

        if license_record:
            license_record.is_paid = True
            await db.commit()
            print(f"✅ License {invoice_id} activated via Stripe.")
