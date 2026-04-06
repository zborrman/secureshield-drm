"""
tests/test_provisioning.py
───────────────────────────
Tests for POST /api/provision — zero-friction SMB onboarding endpoint.

Coverage
────────
  Trial:  email required, key returned, expires_at set
  Trial:  duplicate email → 403
  Trial:  missing email → 400
  Paid:   valid paid license → 200 + api_key
  Paid:   unknown key → 401
  Paid:   unpaid license → 402
  Paid:   expired license → 410
  Bad:    no email + no license_key → 400
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from datetime import UTC, datetime, timedelta
from httpx import AsyncClient, ASGITransport

from main import app
import models


@pytest.mark.asyncio
async def test_trial_issues_key(async_client):
    resp = await async_client.post("/api/provision", json={
        "email": "cto@acme.com",
        "is_trial": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "trial"
    assert data["api_key"].startswith("SWT-")
    assert data["plan"] == "trial"
    assert data["expires_at"] is not None


@pytest.mark.asyncio
async def test_trial_duplicate_email_403(async_client, async_db):
    # First trial
    await async_client.post("/api/provision", json={
        "email": "double@corp.com",
        "is_trial": True,
    })
    # Second trial — same email
    resp = await async_client.post("/api/provision", json={
        "email": "double@corp.com",
        "is_trial": True,
    })
    assert resp.status_code == 403
    assert "already been issued" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_trial_no_email_400(async_client):
    resp = await async_client.post("/api/provision", json={
        "is_trial": True,
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_trial_email_case_insensitive(async_client):
    """Upper-case email should be normalised and treated as same as lower-case."""
    await async_client.post("/api/provision", json={
        "email": "Boss@Company.COM",
        "is_trial": True,
    })
    resp = await async_client.post("/api/provision", json={
        "email": "boss@company.com",
        "is_trial": True,
    })
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_paid_valid_license(async_client, async_db):
    """Paid + active license should validate and return api_key."""
    # Insert a paid license directly
    lic = models.License(
        invoice_id   = "SW-SMB-001",
        license_key  = "SW-SMB-VALID-KEY-001",
        is_paid      = True,
        owner_id     = "customer-1",
        owner_email  = "customer@smb.com",
        max_sessions = 5,
    )
    async_db.add(lic)
    await async_db.commit()

    resp = await async_client.post("/api/provision", json={
        "license_key": "SW-SMB-VALID-KEY-001",
        "is_trial": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "paid"
    assert data["api_key"] == "SW-SMB-VALID-KEY-001"
    assert data["plan"] == "smb"


@pytest.mark.asyncio
async def test_paid_unknown_key_401(async_client):
    resp = await async_client.post("/api/provision", json={
        "license_key": "SW-DOES-NOT-EXIST",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_paid_unpaid_license_402(async_client, async_db):
    lic = models.License(
        invoice_id  = "SW-SMB-UNPAID",
        license_key = "SW-UNPAID-KEY",
        is_paid     = False,
        owner_id    = "customer-unpaid",
    )
    async_db.add(lic)
    await async_db.commit()

    resp = await async_client.post("/api/provision", json={
        "license_key": "SW-UNPAID-KEY",
    })
    assert resp.status_code == 402


@pytest.mark.asyncio
async def test_paid_expired_license_410(async_client, async_db):
    past = datetime.now(UTC) - timedelta(days=1)
    lic = models.License(
        invoice_id  = "SW-SMB-EXPIRED",
        license_key = "SW-EXPIRED-KEY",
        is_paid     = True,
        owner_id    = "customer-expired",
        expires_at  = past.replace(tzinfo=None),  # stored as naive UTC
    )
    async_db.add(lic)
    await async_db.commit()

    resp = await async_client.post("/api/provision", json={
        "license_key": "SW-EXPIRED-KEY",
    })
    assert resp.status_code == 410


@pytest.mark.asyncio
async def test_no_payload_400(async_client):
    """Neither trial nor license_key → 400."""
    resp = await async_client.post("/api/provision", json={})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_enterprise_plan_detected(async_client, async_db):
    lic = models.License(
        invoice_id  = "SW-ENT-BIGCORP-001",
        license_key = "SW-ENT-KEY-001",
        is_paid     = True,
        owner_id    = "bigcorp",
    )
    async_db.add(lic)
    await async_db.commit()

    resp = await async_client.post("/api/provision", json={
        "license_key": "SW-ENT-KEY-001",
    })
    assert resp.status_code == 200
    assert resp.json()["plan"] == "enterprise"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def async_client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def async_db():
    """Yield a live DB session for direct model insertion in tests."""
    from conftest import TestSessionLocal
    async with TestSessionLocal() as session:
        yield session
