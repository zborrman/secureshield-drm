import stripe
import os
from database import SessionLocal
import models
from sqlalchemy.future import select
from logging_config import get_logger

logger = get_logger(__name__)

stripe.api_key = os.getenv("STRIPE_API_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


async def handle_payment_success(invoice_id: str) -> None:
    """Activate the license matching invoice_id after a successful Stripe payment."""
    async with SessionLocal() as db:
        result = await db.execute(
            select(models.License).where(models.License.invoice_id == invoice_id)
        )
        license_record = result.scalars().first()

        if license_record:
            license_record.is_paid = True
            await db.commit()
            logger.info("stripe_payment_success", extra={"invoice_id": invoice_id})
        else:
            logger.warning("stripe_payment_no_license", extra={"invoice_id": invoice_id})
