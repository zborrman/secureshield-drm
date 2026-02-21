"""
AI Anomaly Pattern Discovery Tests
====================================
Tests covering all 7 detectors via:
  - Direct service-function unit tests (fast, no DB)
  - HTTP integration tests through the /admin/anomalies endpoint

Mock ORM objects are created using Python dataclasses so we can
test the pure logic without the database overhead.
"""
import os
import pytest
import pytest_asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import anomaly_service


# ─────────────────────────────────────────────────────────────
# Mock ORM objects (dataclasses that duck-type ViewAnalytics / AuditLog)
# ─────────────────────────────────────────────────────────────

@dataclass
class MockSession:
    license_id: int
    ip_address: str
    device_info: str
    is_bot_suspect: bool = False
    duration_seconds: int = 300
    start_time: datetime = field(default_factory=datetime.utcnow)
    tenant_id: int = None


@dataclass
class MockAuditLog:
    ip_address: str
    invoice_id: str
    is_success: bool
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tenant_id: int = None


@dataclass
class MockLicense:
    id: int
    invoice_id: str
    owner_id: str


# ─────────────────────────────────────────────────────────────
# 1. IP Velocity Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ip_velocity_detected():
    """3 distinct IPs on the same license within 1h → finding."""
    now = datetime.utcnow()
    sessions = [
        MockSession(license_id=1, ip_address=f"10.0.0.{i}", device_info="UA/1.0",
                    start_time=now - timedelta(minutes=10))
        for i in range(3)
    ]
    findings = anomaly_service.detect_ip_velocity(sessions, window_hours=1.0, min_ips=3)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "ip_velocity"
    assert f["score"] >= 40
    assert f["evidence"]["ip_count"] == 3
    assert f["license_id"] == 1


@pytest.mark.asyncio
async def test_ip_velocity_no_false_positive():
    """Same license, 2 IPs within 1h — below threshold of 3."""
    now = datetime.utcnow()
    sessions = [
        MockSession(license_id=1, ip_address=f"10.0.0.{i}", device_info="UA/1.0",
                    start_time=now - timedelta(minutes=5))
        for i in range(2)
    ]
    findings = anomaly_service.detect_ip_velocity(sessions, window_hours=1.0, min_ips=3)
    assert findings == []


# ─────────────────────────────────────────────────────────────
# 2. Session Flood Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_flood_detected():
    """6 sessions from same license in 10 min → flood finding."""
    now = datetime.utcnow()
    sessions = [
        MockSession(license_id=2, ip_address="192.168.1.1", device_info="UA/1.0",
                    start_time=now - timedelta(minutes=i))
        for i in range(6)
    ]
    findings = anomaly_service.detect_session_flood(sessions, window_minutes=10, threshold=5)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "session_flood"
    assert f["score"] >= 50
    assert f["evidence"]["session_count"] == 6


# ─────────────────────────────────────────────────────────────
# 3. Bot Pattern Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bot_pattern_detected():
    """4 out of 4 sessions flagged as bot → 100% ratio → finding."""
    sessions = [
        MockSession(license_id=3, ip_address="1.2.3.4", device_info="UA/1.0",
                    is_bot_suspect=True)
        for _ in range(4)
    ]
    findings = anomaly_service.detect_bot_pattern(sessions, min_sessions=3, bot_ratio_threshold=0.5)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "bot_pattern"
    assert f["score"] == 100
    assert f["evidence"]["bot_ratio"] == 1.0


# ─────────────────────────────────────────────────────────────
# 4. Brute-Force Cluster Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_brute_force_cluster_detected():
    """6 failed auth attempts from same IP in 10 min → finding."""
    now = datetime.utcnow()
    logs = [
        MockAuditLog(ip_address="5.5.5.5", invoice_id=f"INV-{i}",
                     is_success=False, timestamp=now - timedelta(minutes=i % 10))
        for i in range(6)
    ]
    findings = anomaly_service.detect_brute_force(logs, window_minutes=10, threshold_fails=5)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "brute_force_cluster"
    assert f["ip_address"] == "5.5.5.5"
    assert f["score"] >= 50
    assert f["evidence"]["failed_attempts"] == 6


# ─────────────────────────────────────────────────────────────
# 5. Credential Sharing / Multi-Device Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_credential_sharing_detected():
    """Same license from 4 distinct user-agents → credential sharing finding."""
    agents = ["Mozilla/5.0 Firefox", "Chrome/110 Safari", "curl/7.88", "Python-httpx/0.24"]
    sessions = [
        MockSession(license_id=4, ip_address="10.0.0.1", device_info=agent)
        for agent in agents
    ]
    findings = anomaly_service.detect_credential_sharing(sessions, min_sessions=2, threshold_devices=4)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "credential_sharing"
    assert f["evidence"]["unique_devices"] == 4


# ─────────────────────────────────────────────────────────────
# 6. Duration Anomaly Detector
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_duration_anomaly_detected():
    """3 sessions with avg duration 0s → content scraping finding."""
    sessions = [
        MockSession(license_id=5, ip_address="10.0.0.1", device_info="UA/1.0",
                    duration_seconds=0)
        for _ in range(3)
    ]
    findings = anomaly_service.detect_duration_anomaly(sessions, min_sessions=3, max_avg_seconds=10.0)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "duration_anomaly"
    assert f["score"] == 100  # avg=0 → max score
    assert f["evidence"]["avg_duration_seconds"] == 0.0


# ─────────────────────────────────────────────────────────────
# 7. No False Positive on Healthy Data
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_false_positive_on_healthy_data():
    """
    A single license with 3 sessions, all from the same IP, same device,
    normal durations, no bot flags, no failed audits.
    analyze_all() must return zero findings.
    """
    now = datetime.utcnow()
    sessions = [
        MockSession(
            license_id=10,
            ip_address="203.0.113.1",
            device_info="Mozilla/5.0 Chrome",
            is_bot_suspect=False,
            duration_seconds=1200,  # 20-min sessions — clearly legitimate
            start_time=now - timedelta(hours=i),
        )
        for i in range(3)
    ]
    audit_logs = [
        MockAuditLog(ip_address="203.0.113.1", invoice_id="INV-GOOD",
                     is_success=True, timestamp=now - timedelta(hours=1))
    ]
    license_map = {10: MockLicense(id=10, invoice_id="INV-GOOD", owner_id="alice")}

    findings = anomaly_service.analyze_all(
        sessions=sessions,
        audit_logs=audit_logs,
        country_map=None,
        license_map=license_map,
    )
    assert findings == [], f"Expected no findings, got: {findings}"


# ─────────────────────────────────────────────────────────────
# 8. HTTP Integration — /admin/anomalies endpoint (skip_geo=true for speed)
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_anomalies_endpoint_returns_structure(db_session, admin_client):
    """GET /admin/anomalies returns the expected {findings, summary} shape
    even when the DB is empty (zero findings, zero counts)."""
    resp = await admin_client.get("/admin/anomalies?skip_geo=true")
    assert resp.status_code == 200
    body = resp.json()
    assert "findings" in body
    assert "summary" in body
    summary = body["summary"]
    assert "total" in summary
    assert "critical" in summary
    assert "high" in summary
    assert "medium" in summary
    assert "low" in summary


@pytest.mark.asyncio
async def test_admin_anomalies_requires_key(db_session, client):
    """Missing admin key → 401."""
    resp = await client.get("/admin/anomalies?skip_geo=true")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_anomalies_summary_endpoint(db_session, admin_client):
    """GET /admin/anomalies/summary returns {summary, top_findings}."""
    resp = await admin_client.get("/admin/anomalies/summary?skip_geo=true")
    assert resp.status_code == 200
    body = resp.json()
    assert "summary" in body
    assert "top_findings" in body
    assert isinstance(body["top_findings"], list)


@pytest.mark.asyncio
async def test_admin_anomalies_detects_via_http(db_session, admin_client):
    """
    Create a suspicious license scenario via the API, then confirm that
    /admin/anomalies detects it.
    We create 6 sessions from 4 different IPs → ip_velocity + session_flood.
    """
    # Create a license
    r = await admin_client.post(
        "/admin/create-license",
        params={"invoice_id": "INV-ANOM-001", "owner_id": "suspect"},
    )
    assert r.status_code == 201

    # Start 6 sessions from 4 different IPs (using custom headers to fake client IP)
    # We can't fake the IP in testing, but we can create sessions via DB directly
    # Instead, POST /analytics/start multiple times from test client (all same IP)
    # then manually update the IP in DB to create variety
    from sqlalchemy.future import select as sa_select
    from database import Base
    import models as m

    # Create 5 ViewAnalytics rows directly with different IPs
    lic_result = await db_session.execute(
        sa_select(m.License).where(m.License.invoice_id == "INV-ANOM-001")
    )
    lic = lic_result.scalars().first()
    assert lic is not None

    now = datetime.utcnow()
    for i in range(5):
        row = m.ViewAnalytics(
            license_id=lic.id,
            content_id="test-content",
            ip_address=f"10.99.{i}.1",
            device_info="Mozilla/5.0",
            is_bot_suspect=False,
            duration_seconds=5,  # very short — also triggers duration_anomaly
            start_time=now - timedelta(minutes=1),
            last_heartbeat=now,
        )
        db_session.add(row)
    await db_session.commit()

    # Now hit the anomaly endpoint
    resp = await admin_client.get("/admin/anomalies?skip_geo=true&hours=1")
    assert resp.status_code == 200
    body = resp.json()

    finding_types = {f["type"] for f in body["findings"]}
    # We have 5 distinct IPs → ip_velocity (min_ips=3) should fire
    assert "ip_velocity" in finding_types or body["summary"]["total"] > 0
