"""
ARQ background worker — SecureShield DRM.

Runs as a separate process alongside the FastAPI app:

    arq worker.WorkerSettings

Task catalogue
──────────────
  task_send_license_email   — deliver license key via SMTP (fire-and-forget from admin router)
  task_fire_geo_webhook     — POST to GEO_WEBHOOK_URL (fire-and-forget from auth router)

Architecture
────────────
  - Broker: Redis (same instance already used for sessions/cache)
  - Queue: ARQ default queue ("arq:queue")
  - Retry: 3 attempts, 5 s backoff
  - Serialisation: ARQ built-in (msgpack/pickle under the hood, no extra deps)

The FastAPI app enqueues jobs via queue_service.enqueue(); the worker
consumes them independently so slow SMTP / webhook calls never block
HTTP request handlers.
"""

from __future__ import annotations

import os
from typing import Any

from arq import cron
from arq.connections import RedisSettings

import email_service
import geo_service
from logging_config import get_logger

logger = get_logger(__name__)

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
GEO_WEBHOOK_URL: str = os.getenv("GEO_WEBHOOK_URL", "")


# ── Task functions ─────────────────────────────────────────────────────────────
# Each task receives `ctx` (ARQ context dict) as the first argument.

async def task_send_license_email(
    ctx: dict[str, Any],
    to: str,
    invoice_id: str,
    plain_key: str,
) -> bool:
    """Send the license key to the owner's email address.

    Retried up to WorkerSettings.max_tries times on failure.
    Returns True on success, False on stub/disabled mode.
    """
    logger.info("worker_email_start", extra={"to": to, "invoice_id": invoice_id})
    result = await email_service.send_license_key(to, invoice_id, plain_key)
    if result:
        logger.info("worker_email_ok", extra={"to": to, "invoice_id": invoice_id})
    else:
        logger.warning("worker_email_failed", extra={"to": to, "invoice_id": invoice_id})
    return result


async def task_fire_geo_webhook(
    ctx: dict[str, Any],
    invoice_id: str,
    country: str,
    ip: str,
) -> None:
    """Notify the operator's geo-block webhook endpoint.

    Uses the GEO_WEBHOOK_URL env var read at worker startup.
    No-op when GEO_WEBHOOK_URL is empty.
    """
    if not GEO_WEBHOOK_URL:
        return
    logger.info(
        "worker_geo_webhook_start",
        extra={"invoice_id": invoice_id, "country": country, "ip": ip},
    )
    await geo_service.fire_geo_block_webhook(GEO_WEBHOOK_URL, invoice_id, country, ip)
    logger.info("worker_geo_webhook_ok", extra={"invoice_id": invoice_id})


# ── Startup / shutdown hooks ───────────────────────────────────────────────────

async def startup(ctx: dict[str, Any]) -> None:
    logger.info("worker_startup", extra={"redis": REDIS_URL})


async def shutdown(ctx: dict[str, Any]) -> None:
    logger.info("worker_shutdown")


# ── Worker settings ────────────────────────────────────────────────────────────

def _redis_settings_from_url(url: str) -> RedisSettings:
    """Parse a redis:// or rediss:// URL into an ARQ RedisSettings object."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int((parsed.path or "/0").lstrip("/") or 0),
        password=parsed.password or None,
        ssl=parsed.scheme == "rediss",
    )


class WorkerSettings:
    """ARQ worker configuration — ``arq worker.WorkerSettings`` to start."""

    functions = [task_send_license_email, task_fire_geo_webhook]
    redis_settings = _redis_settings_from_url(REDIS_URL)

    on_startup = startup
    on_shutdown = shutdown

    # Retry policy
    max_tries = 3
    job_timeout = 30          # seconds before a job is considered stuck
    keep_result = 300         # seconds to keep job result in Redis

    # Concurrency
    max_jobs = 10
