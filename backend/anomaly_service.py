"""
AI Anomaly Pattern Discovery Service
=====================================
Statistical heuristic engine that analyses SecureShield DRM telemetry
(ViewAnalytics + AuditLog) and surfaces suspicious patterns with a
severity score, evidence payload, and natural-language recommendations.

Seven pattern detectors
-----------------------
1. ip_velocity          — many distinct IPs per license in a short window
2. session_flood        — burst of sessions from one license
3. bot_pattern          — high ratio of is_bot_suspect sessions
4. brute_force_cluster  — many failed auth attempts in a short period
5. credential_sharing   — many distinct device / user-agent strings per license
6. duration_anomaly     — very-short-duration sessions at high volume
7. multi_country        — license accessed from multiple countries rapidly

Each detector returns a list of dicts. Call analyze_all() to run all
detectors, merge results, assign UUIDs, enrich with invoice_id, and
sort by score descending.
"""
from __future__ import annotations

import uuid as _uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Severity thresholds ────────────────────────────────────────────────────
CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 40


def _severity(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


# ── 1. IP Velocity ─────────────────────────────────────────────────────────

def detect_ip_velocity(
    sessions: list,
    window_hours: float = 1.0,
    min_ips: int = 3,
) -> list[dict]:
    """
    Flag licenses accessed from >= min_ips distinct IPs within window_hours.
    Score scales from 40 → 100 based on how many extra IPs beyond the threshold.

    Indicates: credential sharing, VPN abuse, or a distributed attack.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=window_hours)
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        if s.start_time >= cutoff:
            by_license[s.license_id].append(s)

    findings = []
    for license_id, recent in by_license.items():
        unique_ips = list({s.ip_address for s in recent if s.ip_address})
        if len(unique_ips) >= min_ips:
            score = min(100, 40 + (len(unique_ips) - min_ips) * 20)
            findings.append({
                "type": "ip_velocity",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "unique_ips": unique_ips,
                    "ip_count": len(unique_ips),
                    "window_hours": window_hours,
                    "session_count": len(recent),
                },
                "recommendation": (
                    f"License accessed from {len(unique_ips)} distinct IPs within "
                    f"{window_hours:.0f}h — possible credential sharing. "
                    "Revoke all active sessions and issue a new key."
                ),
            })
    return findings


# ── 2. Session Flood ───────────────────────────────────────────────────────

def detect_session_flood(
    sessions: list,
    window_minutes: float = 10.0,
    threshold: int = 5,
) -> list[dict]:
    """
    Flag licenses where >= threshold sessions were opened within window_minutes.
    Sudden bursts suggest automated scraping or credential stuffing.
    Score scales from 50 → 100 based on burst size beyond the threshold.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=window_minutes)
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        if s.start_time >= cutoff:
            by_license[s.license_id].append(s)

    findings = []
    for license_id, recent in by_license.items():
        if len(recent) >= threshold:
            score = min(100, 50 + (len(recent) - threshold) * 10)
            findings.append({
                "type": "session_flood",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "session_count": len(recent),
                    "window_minutes": window_minutes,
                    "threshold": threshold,
                    "ips": list({s.ip_address for s in recent if s.ip_address}),
                },
                "recommendation": (
                    f"{len(recent)} sessions opened in {window_minutes:.0f} min — "
                    "possible automated scraping. Review and revoke suspicious sessions."
                ),
            })
    return findings


# ── 3. Bot Pattern ─────────────────────────────────────────────────────────

def detect_bot_pattern(
    sessions: list,
    min_sessions: int = 3,
    bot_ratio_threshold: float = 0.5,
) -> list[dict]:
    """
    Flag licenses where > bot_ratio_threshold of sessions carry is_bot_suspect=True.
    A high ratio indicates systematic automation (not just one accidental fast click).
    Score equals the bot ratio × 100.
    """
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        by_license[s.license_id].append(s)

    findings = []
    for license_id, lic_sessions in by_license.items():
        if len(lic_sessions) < min_sessions:
            continue
        bot_count = sum(1 for s in lic_sessions if s.is_bot_suspect)
        ratio = bot_count / len(lic_sessions)
        if ratio >= bot_ratio_threshold:
            score = min(100, int(ratio * 100))
            findings.append({
                "type": "bot_pattern",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "bot_sessions": bot_count,
                    "total_sessions": len(lic_sessions),
                    "bot_ratio": round(ratio, 3),
                    "threshold": bot_ratio_threshold,
                },
                "recommendation": (
                    f"{bot_count}/{len(lic_sessions)} sessions flagged as bot "
                    f"({int(ratio * 100)}% ratio). Automated extraction likely. "
                    "Revoke the license and generate a Proof-of-Leak report."
                ),
            })
    return findings


# ── 4. Brute-Force Cluster ─────────────────────────────────────────────────

def detect_brute_force(
    audit_logs: list,
    window_minutes: float = 10.0,
    threshold_fails: int = 5,
) -> list[dict]:
    """
    Flag IP addresses generating >= threshold_fails failed auth attempts within
    window_minutes. Groups by IP to catch distributed brute-force across
    multiple invoice IDs from the same source.
    Score scales from 50 → 100 based on fail count beyond the threshold.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=window_minutes)
    fails_by_ip: dict[str, list] = defaultdict(list)
    for log in audit_logs:
        if not log.is_success and log.timestamp >= cutoff and log.ip_address:
            fails_by_ip[log.ip_address].append(log)

    findings = []
    for ip, logs in fails_by_ip.items():
        if len(logs) >= threshold_fails:
            score = min(100, 50 + (len(logs) - threshold_fails) * 5)
            targeted = list({log.invoice_id for log in logs if log.invoice_id})
            findings.append({
                "type": "brute_force_cluster",
                "ip_address": ip,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "failed_attempts": len(logs),
                    "window_minutes": window_minutes,
                    "targeted_invoices": targeted,
                    "unique_invoices_targeted": len(targeted),
                },
                "recommendation": (
                    f"IP {ip} made {len(logs)} failed auth attempts in "
                    f"{window_minutes:.0f} min across {len(targeted)} invoice(s). "
                    "Block this IP at the network or WAF level."
                ),
            })
    return findings


# ── 5. Credential Sharing / Multi-Device ──────────────────────────────────

def detect_credential_sharing(
    sessions: list,
    min_sessions: int = 2,
    threshold_devices: int = 4,
) -> list[dict]:
    """
    Flag licenses with >= threshold_devices distinct user-agent strings.
    Many different user-agents on a single license indicates account sharing.
    Score scales from 30 → 100 based on device count beyond the threshold.
    """
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        by_license[s.license_id].append(s)

    findings = []
    for license_id, lic_sessions in by_license.items():
        if len(lic_sessions) < min_sessions:
            continue
        unique_agents = list({s.device_info for s in lic_sessions if s.device_info})
        if len(unique_agents) >= threshold_devices:
            score = min(100, 30 + (len(unique_agents) - threshold_devices) * 15)
            findings.append({
                "type": "credential_sharing",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "unique_devices": len(unique_agents),
                    "threshold": threshold_devices,
                    "sample_agents": unique_agents[:5],
                },
                "recommendation": (
                    f"License used from {len(unique_agents)} distinct devices/browsers. "
                    "Single-user licenses should not span many user-agents. "
                    "Investigate possible account sharing."
                ),
            })
    return findings


# ── 6. Duration Anomaly (Content Scraping) ─────────────────────────────────

def detect_duration_anomaly(
    sessions: list,
    min_sessions: int = 3,
    max_avg_seconds: float = 10.0,
) -> list[dict]:
    """
    Flag licenses where the mean session duration is suspiciously short.
    Very short sessions (< 10 s average) suggest automated download/scraping.
    Score inversely proportional to average duration, reaching 100 at 0 s.
    """
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        by_license[s.license_id].append(s)

    findings = []
    for license_id, lic_sessions in by_license.items():
        if len(lic_sessions) < min_sessions:
            continue
        durations = [s.duration_seconds for s in lic_sessions]
        avg = sum(durations) / len(durations)
        if avg <= max_avg_seconds:
            # Score 100 at avg=0, score 20 at avg=max_avg_seconds
            score = min(100, int((1.0 - avg / max_avg_seconds) * 80 + 20))
            findings.append({
                "type": "duration_anomaly",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "avg_duration_seconds": round(avg, 2),
                    "max_avg_threshold_seconds": max_avg_seconds,
                    "session_count": len(lic_sessions),
                    "durations_sample": sorted(durations)[:10],
                },
                "recommendation": (
                    f"Mean session duration is {avg:.1f}s — far below normal viewing "
                    f"time. Automated content extraction likely. "
                    "Review vault access logs and revoke if confirmed."
                ),
            })
    return findings


# ── 7. Multi-Country Rapid Access ──────────────────────────────────────────

def detect_multi_country(
    sessions: list,
    country_map: dict[str, str],
    window_hours: float = 2.0,
    min_countries: int = 2,
) -> list[dict]:
    """
    Flag licenses accessed from >= min_countries distinct countries in window_hours.
    Geographically impossible for a single user → credential sharing or VPN abuse.
    Requires a pre-built ip→country_code mapping (use geo_service on caller side).
    Score scales from 40 → 100 based on country count beyond the threshold.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=window_hours)
    by_license: dict[int, list] = defaultdict(list)
    for s in sessions:
        if s.start_time >= cutoff:
            by_license[s.license_id].append(s)

    findings = []
    for license_id, recent in by_license.items():
        countries = list({
            country_map.get(s.ip_address, "")
            for s in recent
            if country_map.get(s.ip_address, "") not in ("", "XX")
        })
        if len(countries) >= min_countries:
            score = min(100, 40 + (len(countries) - min_countries) * 20)
            findings.append({
                "type": "multi_country",
                "license_id": license_id,
                "score": score,
                "severity": _severity(score),
                "evidence": {
                    "countries": countries,
                    "country_count": len(countries),
                    "window_hours": window_hours,
                },
                "recommendation": (
                    f"License used from {len(countries)} countries "
                    f"({', '.join(countries)}) within {window_hours:.0f}h — "
                    "geographically impossible for a single user. "
                    "Credential sharing or VPN abuse highly probable."
                ),
            })
    return findings


# ── Master Analysis Function ────────────────────────────────────────────────

def build_summary(findings: list[dict]) -> dict:
    """Return a severity-breakdown summary dict for the given findings."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
    }


def analyze_all(
    sessions: list,
    audit_logs: list,
    country_map: dict[str, str] | None = None,
    license_map: dict[int, Any] | None = None,
) -> list[dict]:
    """
    Run all seven detectors and return a unified findings list sorted by
    score descending.

    Each finding is enriched with:
      - anomaly_id   : UUID4 string
      - detected_at  : ISO-8601 UTC string
      - invoice_id   : resolved from license_map (None if map absent)
      - owner_id     : resolved from license_map (None if map absent)

    Parameters
    ----------
    sessions     : list of ViewAnalytics ORM rows
    audit_logs   : list of AuditLog ORM rows
    country_map  : optional {ip_address -> ISO-3166 country_code} dict
    license_map  : optional {license_id -> License ORM row} dict
    """
    findings: list[dict] = []
    findings += detect_ip_velocity(sessions)
    findings += detect_session_flood(sessions)
    findings += detect_bot_pattern(sessions)
    findings += detect_brute_force(audit_logs)
    findings += detect_credential_sharing(sessions)
    findings += detect_duration_anomaly(sessions)
    if country_map:
        findings += detect_multi_country(sessions, country_map)

    now_str = datetime.now(timezone.utc).isoformat()
    for f in findings:
        f["anomaly_id"] = str(_uuid.uuid4())
        f["detected_at"] = now_str

        # Resolve license_id → invoice_id / owner_id
        if license_map and "license_id" in f:
            lic = license_map.get(f["license_id"])
            f["invoice_id"] = lic.invoice_id if lic else None
            f["owner_id"] = lic.owner_id if lic else None
        elif "license_id" in f:
            f.setdefault("invoice_id", None)
            f.setdefault("owner_id", None)

    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings


# ── Orchestration helper (shared by admin + tenant routers) ────────────────

async def run_anomaly_analysis(
    db: "AsyncSession",
    hours: float,
    min_score: int,
    skip_geo: bool,
    tenant_id: int | None = None,
) -> tuple[list[dict], dict]:
    """
    Query telemetry for the given time window, run all detectors, and return
    (findings, summary).  Optionally scoped to a specific tenant_id.

    Moved here from routers/admin.py so both the admin and tenant routers
    can import without creating a cross-router dependency.
    """
    # Import inside function to avoid circular imports at module load time
    from sqlalchemy.future import select
    import models
    import geo_service

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)

    session_q = select(models.ViewAnalytics).where(
        models.ViewAnalytics.start_time >= cutoff
    )
    if tenant_id is not None:
        session_q = session_q.where(models.ViewAnalytics.tenant_id == tenant_id)
    sessions_result = await db.execute(session_q)
    sessions = sessions_result.scalars().all()

    audit_q = select(models.AuditLog).where(models.AuditLog.timestamp >= cutoff)
    if tenant_id is not None:
        audit_q = audit_q.where(models.AuditLog.tenant_id == tenant_id)
    audit_result = await db.execute(audit_q)
    audit_logs = audit_result.scalars().all()

    license_ids = list({s.license_id for s in sessions})
    license_map: dict[int, models.License] = {}
    if license_ids:
        lic_result = await db.execute(
            select(models.License).where(models.License.id.in_(license_ids))
        )
        for lic in lic_result.scalars().all():
            license_map[lic.id] = lic

    country_map: dict[str, str] | None = None
    if not skip_geo and sessions:
        unique_ips = list({s.ip_address for s in sessions if s.ip_address})
        country_map = {}
        for ip in unique_ips:
            try:
                country_map[ip] = await geo_service.get_country_code(ip)
            except Exception:
                country_map[ip] = ""

    findings = analyze_all(
        sessions=sessions,
        audit_logs=audit_logs,
        country_map=country_map,
        license_map=license_map,
    )
    if min_score > 0:
        findings = [f for f in findings if f["score"] >= min_score]

    summary = build_summary(findings)
    return findings, summary
