"""
Queue service — thin enqueue helpers used by FastAPI routers.

Routers call ``enqueue_email()`` / ``enqueue_geo_webhook()`` instead of
awaiting the blocking operation inline.  If the Redis broker is unavailable
the function falls back to executing the task immediately in-process so no
work is silently dropped.

Usage
─────
    from queue_service import enqueue_email, enqueue_geo_webhook

    # Inside a route handler — non-blocking:
    await enqueue_email(to=owner_email, invoice_id=invoice_id, plain_key=key)
    await enqueue_geo_webhook(invoice_id=invoice_id, country=country, ip=ip)
"""

from __future__ import annotations

import os
from logging_config import get_logger

logger = get_logger(__name__)

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ARQ pool — initialised lazily on first enqueue call.
_pool = None


async def _get_pool():
    """Return (and lazily create) the ARQ Redis connection pool."""
    global _pool
    if _pool is None:
        try:
            from arq import create_pool
            from worker import _redis_settings_from_url
            _pool = await create_pool(_redis_settings_from_url(REDIS_URL))
        except Exception as exc:
            logger.warning("queue_pool_init_failed", extra={"error": str(exc)})
    return _pool


async def enqueue_email(to: str, invoice_id: str, plain_key: str) -> None:
    """Enqueue an email delivery job.

    Falls back to inline execution if the queue broker is unavailable.
    """
    if not to:
        return

    pool = await _get_pool()
    if pool is not None:
        try:
            await pool.enqueue_job("task_send_license_email", to, invoice_id, plain_key)
            logger.info("queue_email_enqueued", extra={"to": to, "invoice_id": invoice_id})
            return
        except Exception as exc:
            logger.warning(
                "queue_enqueue_failed",
                extra={"task": "task_send_license_email", "error": str(exc)},
            )

    # Fallback: execute inline so the email is never silently dropped
    logger.info("queue_email_inline_fallback", extra={"invoice_id": invoice_id})
    import email_service
    await email_service.send_license_key(to, invoice_id, plain_key)


async def enqueue_geo_webhook(invoice_id: str, country: str, ip: str) -> None:
    """Enqueue a geo-block webhook notification job.

    Falls back to inline execution if the queue broker is unavailable.
    """
    geo_url = os.getenv("GEO_WEBHOOK_URL", "")
    if not geo_url:
        return

    pool = await _get_pool()
    if pool is not None:
        try:
            await pool.enqueue_job("task_fire_geo_webhook", invoice_id, country, ip)
            logger.info(
                "queue_geo_webhook_enqueued",
                extra={"invoice_id": invoice_id, "country": country},
            )
            return
        except Exception as exc:
            logger.warning(
                "queue_enqueue_failed",
                extra={"task": "task_fire_geo_webhook", "error": str(exc)},
            )

    # Fallback: execute inline
    logger.info("queue_geo_webhook_inline_fallback", extra={"invoice_id": invoice_id})
    import geo_service
    await geo_service.fire_geo_block_webhook(geo_url, invoice_id, country, ip)


async def close_pool() -> None:
    """Close the ARQ connection pool — call from FastAPI lifespan shutdown."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
