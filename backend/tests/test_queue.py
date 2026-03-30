"""
Message queue tests — ARQ integration layer.

All external I/O (Redis, SMTP, HTTP webhooks) is mocked so no real services
are required.  Tests verify:

  1. enqueue_email() calls pool.enqueue_job with correct arguments
  2. enqueue_geo_webhook() calls pool.enqueue_job with correct arguments
  3. enqueue_geo_webhook() is a no-op when GEO_WEBHOOK_URL is not set
  4. enqueue_email() falls back to inline send when pool is unavailable
  5. enqueue_geo_webhook() falls back to inline fire when pool is unavailable
  6. task_send_license_email() calls email_service.send_license_key
  7. task_fire_geo_webhook() calls geo_service.fire_geo_block_webhook
  8. task_fire_geo_webhook() is a no-op when GEO_WEBHOOK_URL is not set
  9. POST /admin/create-license enqueues email (not inline send) when owner_email set
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "test-admin-key")


# ── Unit tests: queue_service ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enqueue_email_calls_enqueue_job():
    """enqueue_email() must call pool.enqueue_job with correct task name and args."""
    mock_pool = AsyncMock()
    mock_pool.enqueue_job = AsyncMock()

    with patch("queue_service._pool", mock_pool):
        import queue_service
        await queue_service.enqueue_email("user@example.com", "INV-001", "SK-abc")

    mock_pool.enqueue_job.assert_awaited_once_with(
        "task_send_license_email", "user@example.com", "INV-001", "SK-abc"
    )


@pytest.mark.asyncio
async def test_enqueue_geo_webhook_calls_enqueue_job(monkeypatch):
    """enqueue_geo_webhook() must call pool.enqueue_job with correct args."""
    monkeypatch.setenv("GEO_WEBHOOK_URL", "https://hooks.example.com/geo")
    mock_pool = AsyncMock()
    mock_pool.enqueue_job = AsyncMock()

    with patch("queue_service._pool", mock_pool):
        import queue_service
        import importlib
        importlib.reload(queue_service)
        with patch("queue_service._pool", mock_pool):
            await queue_service.enqueue_geo_webhook("INV-001", "RU", "1.2.3.4")

    mock_pool.enqueue_job.assert_awaited_once_with(
        "task_fire_geo_webhook", "INV-001", "RU", "1.2.3.4"
    )


@pytest.mark.asyncio
async def test_enqueue_geo_webhook_noop_without_url(monkeypatch):
    """enqueue_geo_webhook() must be a no-op when GEO_WEBHOOK_URL is empty."""
    monkeypatch.setenv("GEO_WEBHOOK_URL", "")
    mock_pool = AsyncMock()
    mock_pool.enqueue_job = AsyncMock()

    with patch("queue_service._pool", mock_pool):
        import queue_service
        await queue_service.enqueue_geo_webhook("INV-001", "RU", "1.2.3.4")

    mock_pool.enqueue_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_enqueue_email_falls_back_inline_when_pool_unavailable():
    """When pool is None and cannot be created, email is sent inline."""
    mock_send = AsyncMock(return_value=True)

    with patch("queue_service._pool", None):
        with patch("queue_service._get_pool", AsyncMock(return_value=None)):
            with patch("email_service.send_license_key", mock_send):
                import queue_service
                await queue_service.enqueue_email("user@example.com", "INV-002", "SK-xyz")

    mock_send.assert_awaited_once_with("user@example.com", "INV-002", "SK-xyz")


@pytest.mark.asyncio
async def test_enqueue_geo_webhook_falls_back_inline_when_pool_unavailable(monkeypatch):
    """When pool is None, geo webhook is fired inline."""
    monkeypatch.setenv("GEO_WEBHOOK_URL", "https://hooks.example.com/geo")
    mock_fire = AsyncMock()

    with patch("queue_service._pool", None):
        with patch("queue_service._get_pool", AsyncMock(return_value=None)):
            with patch("geo_service.fire_geo_block_webhook", mock_fire):
                import queue_service
                import importlib
                importlib.reload(queue_service)
                with patch("queue_service._pool", None):
                    with patch("queue_service._get_pool", AsyncMock(return_value=None)):
                        await queue_service.enqueue_geo_webhook("INV-003", "CN", "5.6.7.8")

    mock_fire.assert_awaited_once()


# ── Unit tests: worker task functions ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_task_send_license_email_calls_service():
    """task_send_license_email() must delegate to email_service.send_license_key."""
    mock_send = AsyncMock(return_value=True)

    with patch("email_service.send_license_key", mock_send):
        import worker
        ctx: dict = {}
        result = await worker.task_send_license_email(ctx, "a@b.com", "INV-X", "SK-1")

    assert result is True
    mock_send.assert_awaited_once_with("a@b.com", "INV-X", "SK-1")


@pytest.mark.asyncio
async def test_task_fire_geo_webhook_calls_service(monkeypatch):
    """task_fire_geo_webhook() must delegate to geo_service.fire_geo_block_webhook."""
    monkeypatch.setenv("GEO_WEBHOOK_URL", "https://hooks.example.com/geo")
    mock_fire = AsyncMock()

    with patch("geo_service.fire_geo_block_webhook", mock_fire):
        import worker
        import importlib
        importlib.reload(worker)
        with patch("geo_service.fire_geo_block_webhook", mock_fire):
            ctx: dict = {}
            await worker.task_fire_geo_webhook(ctx, "INV-Y", "DE", "9.10.11.12")

    mock_fire.assert_awaited_once()


@pytest.mark.asyncio
async def test_task_fire_geo_webhook_noop_without_url(monkeypatch):
    """task_fire_geo_webhook() must be a no-op when GEO_WEBHOOK_URL is not set."""
    monkeypatch.setenv("GEO_WEBHOOK_URL", "")
    mock_fire = AsyncMock()

    with patch("geo_service.fire_geo_block_webhook", mock_fire):
        import worker
        import importlib
        importlib.reload(worker)
        ctx: dict = {}
        await worker.task_fire_geo_webhook(ctx, "INV-Z", "RU", "1.1.1.1")

    mock_fire.assert_not_awaited()


# ── Integration test: /admin/create-license enqueues email ────────────────────

@pytest.mark.asyncio
async def test_create_license_enqueues_email_not_inline(client, db_session):
    """POST /admin/create-license must call queue_service.enqueue_email,
    not email_service.send_license_key directly."""
    mock_enqueue = AsyncMock()
    mock_inline = AsyncMock(return_value=True)

    with patch("queue_service.enqueue_email", mock_enqueue):
        with patch("email_service.send_license_key", mock_inline):
            resp = await client.post(
                "/admin/create-license",
                params={
                    "invoice_id": "QUEUE-TEST-001",
                    "owner_id":   "queue-tester",
                    "owner_email": "queue@example.com",
                },
                headers={"X-Admin-Key": _ADMIN_KEY},
            )

    assert resp.status_code == 201
    mock_enqueue.assert_awaited_once()
    # Confirm the inline send was NOT called directly
    mock_inline.assert_not_awaited()
