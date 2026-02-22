import stripe
import os
from database import SessionLocal
import models
from sqlalchemy.future import select
from logging_config import get_logger
from tenacity import retry, stop_after_attempt, wait_exponential

logger = get_logger(__name__)

stripe.api_key = os.getenv("STRIPE_API_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
async def handle_payment_success(invoice_id: str) -> None:
    """Activate the license matching invoice_id after a successful Stripe payment.

    Retries up to 3 times with exponential backoff on any transient error
    (DB connection drops, temporary I/O failures, etc.).  Business-logic
    outcomes (license not found) are logged as warnings and do not raise,
    so they are not retried.
    """
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
