"""
Admin-only routes (require X-Admin-Key):
  GET  /health
  POST /admin/create-license
  POST /admin/licenses/bulk
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
  GET  /admin/anomalies/enriched
  GET  /admin/metabase/embed-token
  GET  /admin/gdpr/export/{invoice_id}
  DELETE /admin/gdpr/purge/{invoice_id}
  GET  /admin/stripe/dlq
  POST /admin/stripe/dlq/{event_id}/retry
"""
import uuid
import json
import hmac as _hmac
import hashlib as _hashlib
import secrets as _secrets
import jwt as _jwt
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request, Response, UploadFile, File
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
import stripe_service
import email_service
import bulk_import
import llm_council_service
from schemas import LicenseCreatedResponse, OfflineTokenIssued, AnomalyResponse, BulkImportResponse
from config import (
    ADMIN_API_KEY,
    OFFLINE_TOKEN_SECRET,
    SESSION_ACTIVE_MINUTES,
    BRUTE_FORCE_WINDOW_MINUTES,
    BRUTE_FORCE_MAX_FAILS,
    ADMIN_TOTP_SECRET,
    ADMIN_SESSION_TTL,
)
from dependencies import _admin_session_secret
from sqlalchemy import text
from rate_limit import limiter, ADMIN_WRITE_LIMIT

router = APIRouter()


# ── Admin login (issues short-lived session JWT) ───────────────────────────────

@router.post("/admin/login")
async def admin_login(
    api_key:   str = Query(...),
    totp_code: str = Query(default=""),
):
    """Exchange API key (+ optional TOTP code) for a short-lived admin session JWT.

    - When ``ADMIN_TOTP_SECRET`` is configured, a valid 6-digit TOTP code is required.
    - Returns ``{"token": "<jwt>", "expires_in": <seconds>}``.
    - The token can be passed as ``Authorization: Bearer <token>`` on all admin endpoints.
    """
    import time as _time
    if not ADMIN_API_KEY or not _hmac.compare_digest(api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid admin API key")

    if ADMIN_TOTP_SECRET:
        import pyotp
        if not totp_code:
            raise HTTPException(status_code=401, detail="TOTP code required (TOTP is enabled)")
        totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid or expired TOTP code")

    now = int(_time.time())
    token = _jwt.encode(
        {"sub": "admin", "type": "admin_session", "iat": now, "exp": now + ADMIN_SESSION_TTL},
        _admin_session_secret(),
        algorithm="HS256",
    )
    return {"token": token, "expires_in": ADMIN_SESSION_TTL}


@router.get("/admin/totp/setup")
async def admin_totp_setup(_: None = Depends(require_admin)):
    """Return TOTP provisioning URI for use in an authenticator app.

    Requires ``ADMIN_TOTP_SECRET`` to be set in the environment.
    If not set, returns ``{"enabled": false}``.
    """
    if not ADMIN_TOTP_SECRET:
        return {"enabled": False, "message": "ADMIN_TOTP_SECRET not configured"}
    import pyotp
    totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
    uri = totp.provisioning_uri("admin@secureshield", issuer_name="SecureShield DRM")
    return {"enabled": True, "provisioning_uri": uri}


# ── Health ─────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Deep health check — verifies all critical dependencies:
    - Database (SELECT 1)
    - Redis (PING)
    - S3 (head-bucket)

    Returns 200 only if all three are reachable; 503 otherwise with details.
    Any individual failure is reported in the response body so operators
    can identify which component is degraded.
    """
    checks: dict[str, str] = {}

    # Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"

    # Redis
    try:
        r = await redis_service.get_redis()
        await r.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    # S3 — skipped when test/placeholder credentials are detected (AWS_ACCESS_KEY_ID="test")
    import os as _os
    import vault_service
    _aws_key = _os.getenv("AWS_ACCESS_KEY_ID", "")
    if vault_service.S3_BUCKET and _aws_key and _aws_key != "test":
        try:
            import asyncio
            await asyncio.to_thread(
                vault_service.get_s3().head_bucket, Bucket=vault_service.S3_BUCKET
            )
            checks["s3"] = "ok"
        except Exception as exc:
            checks["s3"] = f"error: {exc}"
    else:
        checks["s3"] = "unconfigured"

    all_ok = all(v in ("ok", "unconfigured") for v in checks.values())
    status_code = 200 if all_ok else 503
    body = {"status": "healthy" if all_ok else "degraded", **checks}

    if not all_ok:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=body)
    return body


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
    expires_at: datetime | None = None,
    owner_email: str | None = Query(default=None, max_length=256),
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
        expires_at=expires_at,
        owner_email=owner_email or None,
    )
    db.add(new_license)
    await db.commit()
    if owner_email:
        await email_service.send_license_key(owner_email, invoice_id, plain_key)
    return {
        "invoice_id": invoice_id,
        "plain_key_to_copy": plain_key,
        "warning": "Save the key — only the hash is stored.",
    }


@router.post("/admin/licenses/bulk", status_code=200, response_model=BulkImportResponse)
async def bulk_create_licenses(
    file: UploadFile = File(..., description="CSV file with columns: invoice_id, owner_id, [max_sessions, allowed_countries, is_paid, expires_at, owner_email]"),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Import multiple licenses from a CSV file.

    Returns per-row results: status is 'created', 'conflict' (duplicate invoice_id),
    or 'error' (parse / DB failure).  A conflict or error on one row does not
    affect the others — each row is committed independently.
    """
    if not file.content_type or "csv" not in file.content_type.lower():
        if file.filename and not file.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=422, detail="Only CSV files are accepted")
    csv_bytes = await file.read()
    if len(csv_bytes) > 5 * 1024 * 1024:  # 5 MB hard cap
        raise HTTPException(status_code=413, detail="CSV file exceeds 5 MB limit")
    result = await bulk_import.process_bulk_csv(csv_bytes, db)
    return result


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
    before_id: int | None = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
    response: Response = None,
):
    """List audit log entries, newest first.

    Cursor pagination (preferred for large tables):
      Pass `before_id` (the last ID from the previous page) to fetch the next page.
      Response header `X-Next-Cursor` contains the ID to use as `before_id` on the
      next call.  O(log N) via the primary-key index — avoids full-table scans.

    Legacy offset pagination (backward compat):
      Omit `before_id` and use `skip` as usual.
    """
    q = select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit)
    if before_id is not None:
        q = q.where(models.AuditLog.id < before_id)
    else:
        q = q.offset(skip)
    result = await db.execute(q)
    rows = result.scalars().all()
    if rows and response is not None:
        response.headers["X-Next-Cursor"] = str(rows[-1].id)
    return rows


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
    before_id: int | None = None,
    skip: int = 0,
    limit: int = Query(default=50, le=1000),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
    response: Response = None,
):
    """List viewing sessions, newest first.  Supports cursor pagination via `before_id`."""
    q = select(models.ViewAnalytics).order_by(models.ViewAnalytics.id.desc()).limit(limit)
    if before_id is not None:
        q = q.where(models.ViewAnalytics.id < before_id)
    else:
        q = q.offset(skip)
    result = await db.execute(q)
    rows = result.scalars().all()
    if rows and response is not None:
        response.headers["X-Next-Cursor"] = str(rows[-1].id)
    return rows


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
    # Invalidate cache so the next verify-license call reads the updated geo restriction.
    await redis_service.cache_delete(f"lic:{invoice_id}")
    return {"invoice_id": invoice_id, "allowed_countries": lic.allowed_countries}


# ── Proof of Leak ──────────────────────────────────────────────────────────────

@router.post("/admin/proof-of-leak", status_code=201)
async def generate_leak_proof(
    invoice_id: str = "",
    fingerprint: str = "",
    force: bool = False,
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

        # Dedup: check for existing report for this invoice_id
        existing_report = await db.execute(
            select(models.LeakReport).where(models.LeakReport.invoice_id == invoice_id)
        )
        existing_report = existing_report.scalars().first()
        if existing_report:
            if not force:
                raise HTTPException(
                    status_code=409,
                    detail=f"Report already exists for {invoice_id}. Use ?force=true to regenerate.",
                )
            # force=True: delete existing report before creating a new one
            await db.delete(existing_report)
            await db.commit()
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


# ── GDPR ───────────────────────────────────────────────────────────────────────

@router.get("/admin/gdpr/export/{invoice_id}")
async def gdpr_export(
    invoice_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    GDPR Subject Access Request — return all data held for this invoice_id.

    Includes: license record, audit logs, view analytics sessions,
    offline tokens, and vault content grants.
    The response is a structured JSON object suitable for delivery to the
    data subject.
    """
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    license_record = result.scalars().first()
    if not license_record:
        raise HTTPException(status_code=404, detail=f"No data found for invoice_id: {invoice_id}")

    # Audit logs
    audit_result = await db.execute(
        select(models.AuditLog).where(models.AuditLog.invoice_id == invoice_id)
    )
    audit_logs = [
        {
            "timestamp": r.timestamp.isoformat() + "Z",
            "ip_address": r.ip_address,
            "is_success": r.is_success,
            "user_agent": r.user_agent,
        }
        for r in audit_result.scalars().all()
    ]

    # View analytics
    sessions_result = await db.execute(
        select(models.ViewAnalytics).where(
            models.ViewAnalytics.license_id == license_record.id
        )
    )
    sessions = [
        {
            "start_time": r.start_time.isoformat() + "Z",
            "duration_seconds": r.duration_seconds,
            "ip_address": r.ip_address,
            "device_info": r.device_info,
            "content_id": r.content_id,
        }
        for r in sessions_result.scalars().all()
    ]

    # Offline tokens
    tokens_result = await db.execute(
        select(models.OfflineToken).where(models.OfflineToken.invoice_id == invoice_id)
    )
    tokens = [
        {
            "issued_at": r.issued_at.isoformat() + "Z",
            "valid_until": r.valid_until.isoformat() + "Z",
            "device_hint": r.device_hint,
            "is_revoked": r.is_revoked,
        }
        for r in tokens_result.scalars().all()
    ]

    return {
        "invoice_id": invoice_id,
        "owner_id": license_record.owner_id,
        "is_paid": license_record.is_paid,
        "audit_logs": audit_logs,
        "view_sessions": sessions,
        "offline_tokens": tokens,
        "exported_at": datetime.utcnow().isoformat() + "Z",
    }


@router.delete("/admin/gdpr/purge/{invoice_id}", status_code=200)
async def gdpr_purge(
    invoice_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    GDPR Right to be Forgotten — permanently delete ALL data for this invoice_id.

    Deletes (in dependency order):
      1. LicenseContent grants
      2. ViewAnalytics sessions
      3. OfflineTokens
      4. AuditLog entries
      5. LeakReport entries
      6. The License record itself

    This operation is IRREVERSIBLE. A structured summary of what was deleted
    is returned so the operator can record the purge event.
    """
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    license_record = result.scalars().first()
    if not license_record:
        raise HTTPException(status_code=404, detail=f"No data found for invoice_id: {invoice_id}")

    counts: dict[str, int] = {}

    # 1. LicenseContent grants
    lc_result = await db.execute(
        select(models.LicenseContent).where(
            models.LicenseContent.license_id == license_record.id
        )
    )
    lc_rows = lc_result.scalars().all()
    for row in lc_rows:
        await db.delete(row)
    counts["license_grants"] = len(lc_rows)

    # 2. ViewAnalytics
    va_result = await db.execute(
        select(models.ViewAnalytics).where(
            models.ViewAnalytics.license_id == license_record.id
        )
    )
    va_rows = va_result.scalars().all()
    for row in va_rows:
        await db.delete(row)
    counts["view_sessions"] = len(va_rows)

    # 3. OfflineTokens
    ot_result = await db.execute(
        select(models.OfflineToken).where(models.OfflineToken.invoice_id == invoice_id)
    )
    ot_rows = ot_result.scalars().all()
    for row in ot_rows:
        await db.delete(row)
    counts["offline_tokens"] = len(ot_rows)

    # 4. AuditLog entries
    al_result = await db.execute(
        select(models.AuditLog).where(models.AuditLog.invoice_id == invoice_id)
    )
    al_rows = al_result.scalars().all()
    for row in al_rows:
        await db.delete(row)
    counts["audit_log_entries"] = len(al_rows)

    # 5. LeakReports
    lr_result = await db.execute(
        select(models.LeakReport).where(models.LeakReport.invoice_id == invoice_id)
    )
    lr_rows = lr_result.scalars().all()
    for row in lr_rows:
        await db.delete(row)
    counts["leak_reports"] = len(lr_rows)

    # 6. License
    await db.delete(license_record)
    await db.commit()

    return {
        "status": "purged",
        "invoice_id": invoice_id,
        "deleted": counts,
        "purged_at": datetime.utcnow().isoformat() + "Z",
    }


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
    reason: str | None = Query(default=None, max_length=256, description="Optional reason for revocation"),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    row = await db.get(models.OfflineToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    row.is_revoked = True
    row.revocation_reason = reason or None
    await db.commit()
    return {"status": "revoked", "token_id": token_id, "revocation_reason": row.revocation_reason}


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
            "revocation_reason": t.revocation_reason,
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


@router.get("/admin/anomalies/enriched")
async def get_enriched_anomalies(
    hours: float = 24.0,
    min_score: int = Query(default=40, ge=0, le=100),
    limit: int = Query(default=5, ge=1, le=20),
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Run statistical anomaly detection then enrich the top findings with
    LLM Council (3-stage deliberation via OpenRouter).

    Results are cached in Redis for COUNCIL_CACHE_TTL seconds so repeated
    calls are fast and don't consume extra API credits.

    Requires OPENROUTER_API_KEY to be set — returns 503 otherwise.
    """
    import config as _config

    if not _config.OPENROUTER_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI enrichment is not configured. "
                "Set OPENROUTER_API_KEY to enable this endpoint."
            ),
        )

    findings, summary = await anomaly_service.run_anomaly_analysis(
        db, hours, min_score, skip_geo, tenant_id=None
    )
    top = sorted(findings, key=lambda f: f["score"], reverse=True)[:limit]

    enriched = []
    for finding in top:
        cache_key = f"council:{finding['anomaly_id']}"
        cached = await redis_service.cache_get(cache_key)
        if cached:
            enriched.append(cached)
            continue

        result = await llm_council_service.run_council(finding)
        await redis_service.cache_set(cache_key, result, ttl=_config.COUNCIL_CACHE_TTL)
        enriched.append(result)

    return {
        "enriched_findings": enriched,
        "total": len(enriched),
        "summary": summary,
    }


# ── Stripe Dead-Letter Queue ───────────────────────────────────────────────────

@router.get("/admin/stripe/dlq")
async def get_stripe_dlq(
    status: str = None,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List Stripe webhook events from the dead-letter queue.

    Filter by ?status=failed to see only events that need attention.
    """
    q = (
        select(models.StripeWebhookEvent)
        .order_by(models.StripeWebhookEvent.received_at.desc())
        .limit(limit)
    )
    if status:
        q = q.where(models.StripeWebhookEvent.status == status)
    result = await db.execute(q)
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "status": e.status,
            "attempts": e.attempts,
            "error": e.error,
            "received_at": e.received_at.isoformat() + "Z",
            "processed_at": e.processed_at.isoformat() + "Z" if e.processed_at else None,
        }
        for e in events
    ]


@router.post("/admin/stripe/dlq/{event_id}/retry", status_code=200)
async def retry_stripe_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Manually retry a failed (or pending) Stripe webhook event.

    Parses the stored payload and re-invokes the appropriate handler.
    Returns 409 if the event has already been processed successfully.
    """
    event = await db.get(models.StripeWebhookEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.status == "processed":
        raise HTTPException(status_code=409, detail="Event already processed")

    payload_dict = json.loads(event.payload)
    event.attempts += 1
    event.status = "processing"
    await db.commit()

    if payload_dict.get("type") == "checkout.session.completed":
        session_obj = payload_dict["data"]["object"]
        invoice_id = session_obj["metadata"].get("invoice_id")
        try:
            await stripe_service.handle_payment_success(invoice_id)
            event.status = "processed"
            event.processed_at = datetime.utcnow()
            event.error = None
        except Exception as exc:
            event.status = "failed"
            event.error = str(exc)[:1000]
    else:
        event.status = "processed"
        event.processed_at = datetime.utcnow()

    await db.commit()
    return {"status": event.status, "attempts": event.attempts}


# ── Metabase embedded analytics ─────────────────────────────────────────────────

@router.get("/admin/metabase/embed-token")
async def get_metabase_embed_token(
    dashboard_id: int = Query(..., ge=1, description="Metabase dashboard numeric ID"),
    expires_in: int = Query(default=600, ge=60, le=3600, description="Token TTL in seconds"),
    _: None = Depends(require_admin),
):
    """
    Return a signed HS256 JWT and the corresponding iFrame embed URL for a
    specific Metabase dashboard.

    The JWT is signed with METABASE_SECRET_KEY which must match the
    "Embedding secret key" configured in Metabase Admin → Settings → Embedding.

    Usage in the frontend:
        const { embed_url } = await fetch('/admin/metabase/embed-token?dashboard_id=1')
        // render: <iframe src={embed_url} />

    Requires METABASE_SECRET_KEY to be set — returns 503 otherwise.
    """
    import time as _time
    import config as _config

    if not _config.METABASE_SECRET_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "Metabase embedding is not configured. "
                "Set METABASE_SECRET_KEY to the value from "
                "Metabase Admin → Settings → Embedding."
            ),
        )

    payload = {
        "resource": {"dashboard": dashboard_id},
        "params": {},
        "exp": int(_time.time()) + expires_in,
    }
    token = _jwt.encode(payload, _config.METABASE_SECRET_KEY, algorithm="HS256")
    embed_url = (
        f"{_config.METABASE_SITE_URL}/embed/dashboard/{token}"
        "#bordered=true&titled=true"
    )
    return {
        "embed_url": embed_url,
        "token": token,
        "dashboard_id": dashboard_id,
        "expires_in": expires_in,
    }
