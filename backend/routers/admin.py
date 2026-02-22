"""
Admin-only routes (require X-Admin-Key):
  GET  /health
  POST /admin/create-license
  GET  /admin/licenses
  GET  /admin/audit-log
  GET  /admin/alerts
  GET  /admin/analytics
  DELETE /admin/analytics/{session_id}
  GET  /admin/sessions/live
  POST /admin/sessions/revoke-all/{invoice_id}
  GET  /admin/events  (SSE)
  PATCH /admin/licenses/{invoice_id}/geo
  POST /admin/proof-of-leak
  GET  /admin/proof-of-leak
  GET  /admin/proof-of-leak/{report_id}
  POST /admin/offline-token
  DELETE /admin/offline-token/{token_id}
  GET  /admin/offline-tokens
  GET  /admin/anomalies
  GET  /admin/anomalies/summary
"""
import uuid
import json
import hmac as _hmac
import hashlib as _hashlib
import secrets as _secrets
import jwt as _jwt
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, require_admin, log_attempt
from auth_utils import hash_license_key
from watermark_service import generate_user_fingerprint
import models
import geo_service
import redis_service
import anomaly_service
from schemas import LicenseCreatedResponse, OfflineTokenIssued, AnomalyResponse
from config import (
    ADMIN_API_KEY,
    OFFLINE_TOKEN_SECRET,
    SESSION_ACTIVE_MINUTES,
    BRUTE_FORCE_WINDOW_MINUTES,
    BRUTE_FORCE_MAX_FAILS,
)
from sqlalchemy import text
from rate_limit import limiter, ADMIN_WRITE_LIMIT

router = APIRouter()


# ── Health ─────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unreachable")


# ── Licenses ───────────────────────────────────────────────────────────────────

@router.post("/admin/create-license", status_code=201, response_model=LicenseCreatedResponse)
@limiter.limit(ADMIN_WRITE_LIMIT)
async def create_license(
    request: Request,
    invoice_id: str = Query(max_length=128),
    owner_id: str = Query(max_length=128),
    max_sessions: int = Query(default=1, ge=1, le=100),
    allowed_countries: str = Query(default="", max_length=512),
    is_paid: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    plain_key = f"SK-{_secrets.token_urlsafe(16)}"
    hashed_key = hash_license_key(plain_key)
    new_license = models.License(
        invoice_id=invoice_id,
        license_key=hashed_key,
        owner_id=owner_id,
        is_paid=is_paid,
        max_sessions=max_sessions,
        allowed_countries=allowed_countries.upper().strip() or None,
    )
    db.add(new_license)
    await db.commit()
    return {
        "invoice_id": invoice_id,
        "plain_key_to_copy": plain_key,
        "warning": "Save the key — only the hash is stored.",
    }


@router.get("/admin/licenses")
async def list_licenses(
    skip: int = 0,
    limit: int = Query(default=50, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.License).offset(skip).limit(limit)
    )
    return result.scalars().all()


# ── Audit & Alerts ─────────────────────────────────────────────────────────────

@router.get("/admin/audit-log")
async def get_audit_log(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.AuditLog)
        .order_by(models.AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/admin/alerts")
async def get_alerts(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    time_threshold = datetime.utcnow() - timedelta(minutes=30)
    result = await db.execute(
        select(models.AuditLog)
        .where(
            models.AuditLog.is_success == False,
            models.AuditLog.timestamp >= time_threshold,
        )
        .order_by(models.AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


# ── Analytics & Sessions ───────────────────────────────────────────────────────

@router.get("/admin/analytics")
async def get_analytics(
    skip: int = 0,
    limit: int = Query(default=50, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.ViewAnalytics)
        .order_by(models.ViewAnalytics.start_time.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.delete("/admin/analytics/{session_id}")
async def revoke_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.ViewAnalytics).where(models.ViewAnalytics.id == session_id)
    )
    view_session = result.scalars().first()
    if not view_session:
        raise HTTPException(status_code=404, detail="Session not found")

    lic_result = await db.execute(
        select(models.License).where(models.License.id == view_session.license_id)
    )
    lic = lic_result.scalars().first()
    invoice_id = lic.invoice_id if lic else ""

    await redis_service.revoke_session(
        session_id=session_id,
        license_id=view_session.license_id,
        invoice_id=invoice_id,
    )
    await db.delete(view_session)
    await db.commit()
    return {"status": "revoked", "session_id": session_id}


@router.get("/admin/sessions/live")
async def get_live_sessions(_: None = Depends(require_admin)):
    return await redis_service.get_live_sessions()


@router.post("/admin/sessions/revoke-all/{invoice_id}")
async def revoke_all_sessions(
    invoice_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    redis_count = await redis_service.revoke_all_for_license(lic.id, invoice_id)

    active_threshold = datetime.utcnow() - timedelta(minutes=SESSION_ACTIVE_MINUTES)
    db_result = await db.execute(
        select(models.ViewAnalytics).where(
            models.ViewAnalytics.license_id == lic.id,
            models.ViewAnalytics.last_heartbeat >= active_threshold,
        )
    )
    db_sessions = db_result.scalars().all()
    for s in db_sessions:
        await db.delete(s)
    await db.commit()

    return {"invoice_id": invoice_id, "revoked_count": max(redis_count, len(db_sessions))}


@router.get("/admin/events")
async def admin_events(
    request: Request,
    x_admin_key: str = Header(default=""),
    admin_key: str = "",
):
    """SSE stream for real-time revocation events.
    Accepts key via X-Admin-Key header or ?admin_key= query param (EventSource fallback)."""
    key = x_admin_key or admin_key
    if not ADMIN_API_KEY or not _hmac.compare_digest(key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")

    async def event_stream():
        r = await redis_service.get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(redis_service.REVOCATION_CHANNEL)
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                if await request.is_disconnected():
                    break
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if msg and msg["type"] == "message":
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": keepalive\n\n"
        finally:
            await pubsub.unsubscribe(redis_service.REVOCATION_CHANNEL)
            await pubsub.aclose()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Geofence ───────────────────────────────────────────────────────────────────

@router.patch("/admin/licenses/{invoice_id}/geo")
async def update_geo_restriction(
    invoice_id: str,
    allowed_countries: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.allowed_countries = allowed_countries.upper().strip() or None
    await db.commit()
    return {"invoice_id": invoice_id, "allowed_countries": lic.allowed_countries}


# ── Proof of Leak ──────────────────────────────────────────────────────────────

@router.post("/admin/proof-of-leak", status_code=201)
async def generate_leak_proof(
    invoice_id: str = "",
    fingerprint: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    if not invoice_id and not fingerprint:
        raise HTTPException(status_code=422, detail="Provide either invoice_id or fingerprint")

    license_record = None
    resolution_method = "direct_invoice_id"

    if invoice_id:
        result = await db.execute(
            select(models.License).where(models.License.invoice_id == invoice_id)
        )
        license_record = result.scalars().first()
        if not license_record:
            raise HTTPException(status_code=404, detail=f"License not found: {invoice_id}")
    else:
        try:
            submitted_fp = int(fingerprint)
        except ValueError:
            raise HTTPException(status_code=422, detail="fingerprint must be a decimal integer")
        all_lics = await db.execute(select(models.License))
        for lic in all_lics.scalars().all():
            if generate_user_fingerprint(lic.owner_id) == submitted_fp:
                license_record = lic
                resolution_method = "fingerprint_match"
                break
        if not license_record:
            raise HTTPException(
                status_code=404, detail=f"No license matches fingerprint {fingerprint}"
            )

    audit_result = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.invoice_id == license_record.invoice_id)
        .order_by(models.AuditLog.timestamp.asc())
    )
    audit_rows = audit_result.scalars().all()

    sessions_result = await db.execute(
        select(models.ViewAnalytics)
        .where(models.ViewAnalytics.license_id == license_record.id)
        .order_by(models.ViewAnalytics.start_time.asc())
    )
    sessions = sessions_result.scalars().all()

    all_ips = list({
        ip for ip in
        [s.ip_address for s in sessions] + [a.ip_address for a in audit_rows]
        if ip
    })
    all_ts = [s.start_time for s in sessions] + [a.timestamp for a in audit_rows]
    computed_fp = str(generate_user_fingerprint(license_record.owner_id))

    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "system": "SecureShield DRM",
        "submitted_fingerprint": fingerprint or computed_fp,
        "resolution": {
            "method": resolution_method,
            "invoice_id": license_record.invoice_id,
            "owner_id": license_record.owner_id,
            "fingerprint": computed_fp,
        },
        "license": {
            "invoice_id": license_record.invoice_id,
            "owner_id": license_record.owner_id,
            "is_paid": license_record.is_paid,
            "max_sessions": license_record.max_sessions,
            "allowed_countries": license_record.allowed_countries,
        },
        "viewing_sessions": [
            {
                "session_id": s.id,
                "content_id": s.content_id,
                "start_time": s.start_time.isoformat() + "Z",
                "last_heartbeat": s.last_heartbeat.isoformat() + "Z",
                "duration_seconds": s.duration_seconds,
                "ip_address": s.ip_address,
                "device_info": s.device_info,
                "is_bot_suspect": s.is_bot_suspect,
            }
            for s in sessions
        ],
        "audit_trail": [
            {
                "timestamp": a.timestamp.isoformat() + "Z",
                "ip_address": a.ip_address,
                "is_success": a.is_success,
                "user_agent": a.user_agent,
            }
            for a in audit_rows
        ],
        "summary": {
            "total_sessions": len(sessions),
            "bot_suspected_sessions": sum(1 for s in sessions if s.is_bot_suspect),
            "unique_ips": all_ips,
            "total_audit_events": len(audit_rows),
            "failed_verifications": sum(1 for a in audit_rows if not a.is_success),
            "first_activity": min(all_ts).isoformat() + "Z" if all_ts else None,
            "last_activity": max(all_ts).isoformat() + "Z" if all_ts else None,
        },
    }

    evidence_json = json.dumps(report_data, sort_keys=True, separators=(",", ":"))
    integrity_hash = "sha256:" + _hashlib.sha256(evidence_json.encode()).hexdigest()

    leak_report = models.LeakReport(
        id=report_data["report_id"],
        invoice_id=license_record.invoice_id,
        submitted_fingerprint=report_data["submitted_fingerprint"],
        evidence_json=evidence_json,
        integrity_hash=integrity_hash,
    )
    db.add(leak_report)
    await db.commit()
    return {**report_data, "integrity_hash": integrity_hash}


@router.get("/admin/proof-of-leak")
async def list_leak_reports(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.LeakReport)
        .order_by(models.LeakReport.generated_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return [
        {
            "report_id": r.id,
            "generated_at": r.generated_at.isoformat() + "Z",
            "invoice_id": r.invoice_id,
            "submitted_fingerprint": r.submitted_fingerprint,
        }
        for r in result.scalars().all()
    ]


@router.get("/admin/proof-of-leak/{report_id}")
async def get_leak_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    row = await db.get(models.LeakReport, report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return {**json.loads(row.evidence_json), "integrity_hash": row.integrity_hash}


# ── Offline Tokens ─────────────────────────────────────────────────────────────

@router.post("/admin/offline-token", status_code=201, response_model=OfflineTokenIssued)
async def issue_offline_token(
    invoice_id: str = Query(max_length=128),
    hours: int = Query(default=24, ge=1, le=168),
    device_hint: str = Query(default="", max_length=256),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    if hours < 1 or hours > 720:
        raise HTTPException(
            status_code=422, detail="hours must be between 1 and 720 (max 30 days)"
        )
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    if not result.scalars().first():
        raise HTTPException(status_code=404, detail="License not found")

    token_id = str(uuid.uuid4())
    now = datetime.utcnow()
    valid_until = now + timedelta(hours=hours)
    payload = {
        "sub": invoice_id,
        "jti": token_id,
        "iat": int(now.timestamp()),
        "exp": int(valid_until.timestamp()),
        "type": "offline",
        "max_offline_hours": hours,
    }
    jwt_token = _jwt.encode(payload, OFFLINE_TOKEN_SECRET, algorithm="HS256")
    db.add(models.OfflineToken(
        id=token_id,
        invoice_id=invoice_id,
        issued_at=now,
        valid_until=valid_until,
        max_offline_hours=hours,
        device_hint=device_hint.strip() or None,
    ))
    await db.commit()
    return {
        "token_id": token_id,
        "invoice_id": invoice_id,
        "valid_until": valid_until.isoformat() + "Z",
        "max_offline_hours": hours,
        "device_hint": device_hint.strip() or None,
        "token": jwt_token,
    }


@router.delete("/admin/offline-token/{token_id}")
async def revoke_offline_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    row = await db.get(models.OfflineToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    row.is_revoked = True
    await db.commit()
    return {"status": "revoked", "token_id": token_id}


@router.get("/admin/offline-tokens")
async def list_offline_tokens(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.OfflineToken)
        .order_by(models.OfflineToken.issued_at.desc())
        .offset(skip)
        .limit(limit)
    )
    now = datetime.utcnow()
    return [
        {
            "token_id": t.id,
            "invoice_id": t.invoice_id,
            "issued_at": t.issued_at.isoformat() + "Z",
            "valid_until": t.valid_until.isoformat() + "Z",
            "max_offline_hours": t.max_offline_hours,
            "device_hint": t.device_hint,
            "is_revoked": t.is_revoked,
            "is_expired": now >= t.valid_until,
            "hours_remaining": max(
                0, int((t.valid_until - now).total_seconds() // 3600)
            ),
        }
        for t in result.scalars().all()
    ]


# ── AI Anomaly Pattern Discovery ───────────────────────────────────────────────

@router.get("/admin/anomalies")
async def get_anomalies(
    hours: float = 24.0,
    min_score: int = 0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    findings, summary = await anomaly_service.run_anomaly_analysis(
        db, hours, min_score, skip_geo, tenant_id=None
    )
    return {"findings": findings, "summary": summary}


@router.get("/admin/anomalies/summary")
async def get_anomalies_summary(
    hours: float = 24.0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    findings, summary = await anomaly_service.run_anomaly_analysis(
        db, hours, min_score=0, skip_geo=skip_geo, tenant_id=None
    )
    return {"summary": summary, "top_findings": findings[:3]}
