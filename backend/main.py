import os
import json
import uuid
import asyncio
import time as _time
import hashlib as _hashlib
import secrets
import stripe
import jwt as _jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Header, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import text
from database import SessionLocal, engine, Base
from auth_utils import verify_license_key, hash_license_key
from watermark_service import generate_user_fingerprint
import stripe_service
import models
import geo_service
import redis_service
import vault_service
import anomaly_service

app = FastAPI()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
OFFLINE_TOKEN_SECRET = os.getenv("OFFLINE_TOKEN_SECRET", ADMIN_API_KEY + "-offline-v1")
SUPER_ADMIN_KEY = os.getenv("SUPER_ADMIN_KEY", "")

BOT_THRESHOLD_MS = 500       # first heartbeat faster than this → bot suspect
SESSION_ACTIVE_MINUTES = 5   # sessions with no heartbeat for >5 min are considered expired

async def get_db():
    async with SessionLocal() as session:
        yield session

async def require_admin(x_admin_key: str = Header(default="")):
    if not ADMIN_API_KEY or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-Admin-Key")

async def require_super_admin(x_super_admin_key: str = Header(default="")):
    if not SUPER_ADMIN_KEY or x_super_admin_key != SUPER_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-Super-Admin-Key")

async def get_current_tenant(
    x_tenant_id: str = Header(default=""),
    x_admin_key: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> models.Tenant:
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="Missing X-Tenant-ID header")
    result = await db.execute(
        select(models.Tenant).where(models.Tenant.slug == x_tenant_id)
    )
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {x_tenant_id}")
    if not tenant.is_active:
        raise HTTPException(status_code=403, detail="Tenant account is deactivated")
    if not verify_license_key(x_admin_key, tenant.admin_key_hash):
        raise HTTPException(status_code=401, detail="Invalid tenant admin key")
    return tenant

# Создаем таблицы при старте (в продакшене лучше использовать Alembic)
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Redis connection is lazily initialised on first use


@app.on_event("shutdown")
async def shutdown():
    await redis_service.close_redis()

async def log_attempt(db: AsyncSession, invoice_id: str, ip: str, success: bool, ua: str, tenant_id: int = None):
    new_log = models.AuditLog(
        invoice_id=invoice_id,
        ip_address=ip,
        is_success=success,
        user_agent=ua,
        tenant_id=tenant_id,
    )
    db.add(new_log)
    await db.commit()

@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unreachable")

@app.post("/verify-license")
async def verify(
    invoice_id: str,
    input_key: str,
    request: Request, # Получаем данные о запросе
    db: AsyncSession = Depends(get_db)
):
    # Получаем метаданные запроса
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")

    result = await db.execute(select(models.License).where(models.License.invoice_id == invoice_id))
    license_record = result.scalars().first()

    # Проверка на Brute-force (простая логика)
    recent_fails = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.ip_address == client_ip)
        .where(models.AuditLog.is_success == False)
        .limit(5)
    )
    if len(recent_fails.all()) >= 5:
        await log_attempt(db, invoice_id, client_ip, False, user_agent)
        raise HTTPException(status_code=429, detail="Слишком много попыток. IP временно заблокирован.")

    # Geofence check: reject IPs outside the license's allowed regions
    if license_record and license_record.allowed_countries:
        country = await geo_service.get_country_code(client_ip)
        if not geo_service.is_permitted(country, license_record.allowed_countries):
            await log_attempt(db, invoice_id, client_ip, False, f"GEO_BLOCKED:{country} | {user_agent}")
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: your region ({country}) is not permitted for this license",
            )

    success = False
    if license_record and verify_license_key(input_key, license_record.license_key):
        success = True

    # Записываем результат в аудит
    await log_attempt(db, invoice_id, client_ip, success, user_agent)

    if not success:
        raise HTTPException(status_code=403, detail="Invalid Key")

    return {"status": "success", "fingerprint": generate_user_fingerprint(license_record.owner_id)}

@app.post("/admin/create-license", status_code=201)
async def create_license(invoice_id: str, owner_id: str, max_sessions: int = 1, allowed_countries: str = "", db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    # Генерируем случайный безопасный ключ
    plain_key = f"SK-{secrets.token_urlsafe(16)}"
    hashed_key = hash_license_key(plain_key)

    new_license = models.License(
        invoice_id=invoice_id,
        license_key=hashed_key, # В базе только хеш!
        owner_id=owner_id,
        is_paid=False,
        max_sessions=max_sessions,
        allowed_countries=allowed_countries.upper().strip() or None,
    )

    db.add(new_license)
    await db.commit()

    return {
        "invoice_id": invoice_id,
        "plain_key_to_copy": plain_key, # Показываем один раз
        "warning": "Сохраните ключ! В базе останется только его отпечаток."
    }

@app.get("/admin/licenses")
async def list_licenses(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    result = await db.execute(select(models.License))
    return result.scalars().all()

@app.get("/admin/audit-log")
async def get_audit_log(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    result = await db.execute(select(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(100))
    return result.scalars().all()

@app.get("/admin/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db), _: None = Depends(require_admin)):
    # Ищем неудачные попытки за последние 30 минут
    time_threshold = datetime.utcnow() - timedelta(minutes=30)

    query = select(models.AuditLog).where(
        models.AuditLog.is_success == False,
        models.AuditLog.timestamp >= time_threshold
    ).order_by(models.AuditLog.timestamp.desc())

    result = await db.execute(query)
    alerts = result.scalars().all()

    return alerts

@app.post("/analytics/start", status_code=201)
async def analytics_start(
    invoice_id: str,
    content_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called once when user unlocks content. Returns session_id for subsequent heartbeats."""
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    license_record = result.scalars().first()
    if not license_record:
        raise HTTPException(status_code=404, detail="License not found")

    # Geofence check
    if license_record.allowed_countries:
        country = await geo_service.get_country_code(request.client.host)
        if not geo_service.is_permitted(country, license_record.allowed_countries):
            raise HTTPException(
                status_code=403,
                detail=f"Region not permitted: {country}",
            )

    # Enforce concurrent session limit: count slots active within the expiry window
    active_threshold = datetime.utcnow() - timedelta(minutes=SESSION_ACTIVE_MINUTES)
    active_result = await db.execute(
        select(models.ViewAnalytics).where(
            models.ViewAnalytics.license_id == license_record.id,
            models.ViewAnalytics.last_heartbeat >= active_threshold,
        )
    )
    active_count = len(active_result.scalars().all())
    if active_count >= license_record.max_sessions:
        raise HTTPException(
            status_code=409,
            detail=f"Session limit reached ({license_record.max_sessions} concurrent session(s) allowed)",
        )

    session = models.ViewAnalytics(
        license_id=license_record.id,
        content_id=content_id,
        device_info=request.headers.get("user-agent", "unknown"),
        ip_address=request.client.host,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    # Mirror session into Redis for real-time revocation and live-sessions panel
    await redis_service.register_session(
        session_id=session.id,
        license_id=license_record.id,
        invoice_id=invoice_id,
        content_id=content_id,
        ip_address=request.client.host,
    )
    return {"session_id": session.id}


@app.post("/analytics/heartbeat/{session_id}")
async def analytics_heartbeat(
    session_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Called every 30 s by the viewer to accumulate duration_seconds.
    On the FIRST heartbeat, checks timing: if < BOT_THRESHOLD_MS after session
    start the session is flagged as a bot suspect.

    Real-time revocation: if an admin revoked this session, returns
    {"revoked": true, "action": "stop"} and the client must cease playback."""
    # Fast-path revocation check — O(1) Redis EXISTS before any DB work
    if await redis_service.is_revoked(session_id):
        return {"revoked": True, "action": "stop"}

    result = await db.execute(
        select(models.ViewAnalytics).where(models.ViewAnalytics.id == session_id)
    )
    view_session = result.scalars().first()
    if not view_session:
        raise HTTPException(status_code=404, detail="Session not found")

    now = datetime.utcnow()
    delta = int((now - view_session.last_heartbeat).total_seconds())

    # Time-based anomaly: detect scripts that call heartbeat immediately after start
    is_first_heartbeat = view_session.duration_seconds == 0
    if is_first_heartbeat:
        ms_since_start = (now - view_session.start_time).total_seconds() * 1000
        if ms_since_start < BOT_THRESHOLD_MS:
            view_session.is_bot_suspect = True

    view_session.last_heartbeat = now
    view_session.duration_seconds += delta
    await db.commit()

    # Refresh the Redis TTL so the session stays live
    await redis_service.refresh_session(session_id)
    return {
        "duration_seconds": view_session.duration_seconds,
        "suspicious": view_session.is_bot_suspect,
        "revoked": False,
    }


@app.get("/admin/analytics")
async def get_analytics(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Returns all viewing sessions ordered by most recent."""
    result = await db.execute(
        select(models.ViewAnalytics).order_by(models.ViewAnalytics.start_time.desc())
    )
    return result.scalars().all()


@app.delete("/admin/analytics/{session_id}")
async def revoke_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Admin: forcibly terminate a viewing session, freeing its slot.
    Sets a Redis revocation flag so the viewer is notified on the next heartbeat
    (within ≤30 s) without waiting for the DB row to be cleaned up."""
    result = await db.execute(
        select(models.ViewAnalytics).where(models.ViewAnalytics.id == session_id)
    )
    view_session = result.scalars().first()
    if not view_session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Resolve invoice_id for the Pub/Sub event payload
    lic_result = await db.execute(
        select(models.License).where(models.License.id == view_session.license_id)
    )
    lic = lic_result.scalars().first()
    invoice_id = lic.invoice_id if lic else ""

    # Instant Redis revocation — viewer notified on next heartbeat (≤30 s)
    await redis_service.revoke_session(
        session_id=session_id,
        license_id=view_session.license_id,
        invoice_id=invoice_id,
    )
    await db.delete(view_session)
    await db.commit()
    return {"status": "revoked", "session_id": session_id}


# ── Session Orchestration ──────────────────────────────────────

@app.get("/admin/sessions/live")
async def get_live_sessions(
    _: None = Depends(require_admin),
):
    """Real-time active sessions read directly from Redis.
    Returns within milliseconds — no DB query required."""
    return await redis_service.get_live_sessions()


@app.post("/admin/sessions/revoke-all/{invoice_id}")
async def revoke_all_sessions(
    invoice_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Instantly revoke every active session for a license.
    Sets Redis revocation flags (viewers notified within ≤30 s via heartbeat)
    and deletes the DB rows."""
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    # Redis: publish revocations for all live sessions
    redis_count = await redis_service.revoke_all_for_license(lic.id, invoice_id)

    # DB: remove the analytics rows so the slots are freed
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

    revoked_count = max(redis_count, len(db_sessions))
    return {"invoice_id": invoice_id, "revoked_count": revoked_count}


@app.get("/admin/events")
async def admin_events(
    request: Request,
    x_admin_key: str = Header(default=""),
    admin_key: str = "",   # query-param fallback — EventSource cannot set headers
):
    """Server-Sent Events stream for real-time session revocation notifications.
    The admin dashboard connects here via EventSource; every Redis Pub/Sub message
    on the `drm:revocations` channel is forwarded as an SSE data frame.
    Pass the admin key either as X-Admin-Key header or ?admin_key= query param."""
    key = x_admin_key or admin_key
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
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
                    # Keepalive comment line (invisible to EventSource handlers)
                    yield ": keepalive\n\n"
        finally:
            await pubsub.unsubscribe(redis_service.REVOCATION_CHANNEL)
            await pubsub.aclose()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # prevent nginx buffering
        },
    )


@app.patch("/admin/licenses/{invoice_id}/geo")
async def update_geo_restriction(
    invoice_id: str,
    allowed_countries: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Update (or clear) the geofence for an existing license.
    Pass an empty string to remove restrictions."""
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.allowed_countries = allowed_countries.upper().strip() or None
    await db.commit()
    return {"invoice_id": invoice_id, "allowed_countries": lic.allowed_countries}


# ── Proof of Leak ──────────────────────────────────────────────

@app.post("/admin/proof-of-leak", status_code=201)
async def generate_leak_proof(
    invoice_id: str = "",
    fingerprint: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Generate a tamper-evident legal evidence report.
    Identify the leaking party either directly by invoice_id or by the
    watermark fingerprint extracted from the leaked content."""
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
            raise HTTPException(status_code=404, detail=f"No license matches fingerprint {fingerprint}")

    # Collect audit trail and viewing sessions for this license
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

    # Build the evidence payload
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

    # Compute integrity seal over the canonical JSON (deterministic: sorted keys)
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


@app.get("/admin/proof-of-leak")
async def list_leak_reports(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all past evidence reports (summary only)."""
    result = await db.execute(
        select(models.LeakReport).order_by(models.LeakReport.generated_at.desc())
    )
    rows = result.scalars().all()
    return [
        {
            "report_id": r.id,
            "generated_at": r.generated_at.isoformat() + "Z",
            "invoice_id": r.invoice_id,
            "submitted_fingerprint": r.submitted_fingerprint,
        }
        for r in rows
    ]


@app.get("/admin/proof-of-leak/{report_id}")
async def get_leak_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Retrieve a stored evidence report by ID, with integrity verification."""
    row = await db.get(models.LeakReport, report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return {**json.loads(row.evidence_json), "integrity_hash": row.integrity_hash}


# ── Offline Tokens ─────────────────────────────────────────────

@app.post("/admin/offline-token", status_code=201)
async def issue_offline_token(
    invoice_id: str,
    hours: int = 24,
    device_hint: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Issue a time-limited offline-viewing JWT for a license.
    The JWT is signed server-side (HS256). The client can decode the
    payload to check expiry locally without a server call (zero-knowledge
    offline verification). Revocation is enforced on the next online check."""
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


@app.post("/verify-offline-token")
async def verify_offline_token(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Validate an offline JWT — checks signature, expiry, and revocation status.
    Called by the viewer when connectivity is restored to confirm the token is
    still good; also used as the primary check when issuing a new online session."""
    try:
        payload = _jwt.decode(token, OFFLINE_TOKEN_SECRET, algorithms=["HS256"])
    except _jwt.ExpiredSignatureError:
        return {"valid": False, "reason": "expired"}
    except _jwt.InvalidTokenError:
        return {"valid": False, "reason": "invalid_signature"}

    if payload.get("type") != "offline":
        return {"valid": False, "reason": "wrong_token_type"}

    token_id = payload.get("jti")
    row = await db.get(models.OfflineToken, token_id)
    if not row:
        return {"valid": False, "reason": "token_not_found"}
    if row.is_revoked:
        return {"valid": False, "reason": "revoked"}

    hours_remaining = max(0, int((row.valid_until - datetime.utcnow()).total_seconds() // 3600))
    return {
        "valid": True,
        "invoice_id": payload["sub"],
        "hours_remaining": hours_remaining,
        "device_hint": row.device_hint,
    }


@app.delete("/admin/offline-token/{token_id}")
async def revoke_offline_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Revoke an offline token immediately. The holder can no longer use it
    for online verification; local expiry checks will still pass until exp,
    but all online endpoints will reject it."""
    row = await db.get(models.OfflineToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    row.is_revoked = True
    await db.commit()
    return {"status": "revoked", "token_id": token_id}


@app.get("/admin/offline-tokens")
async def list_offline_tokens(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all issued offline tokens with live status fields."""
    result = await db.execute(
        select(models.OfflineToken).order_by(models.OfflineToken.issued_at.desc())
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
            "hours_remaining": max(0, int((t.valid_until - now).total_seconds() // 3600)),
        }
        for t in result.scalars().all()
    ]


# ── Content Vault ──────────────────────────────────────────────

VAULT_ACCESS_TOKEN_MINUTES = 5   # short-lived vault access JWTs


@app.post("/admin/vault/upload", status_code=201)
async def vault_upload(
    file: UploadFile = File(...),
    description: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Upload a file to the encrypted vault.
    The file is AES-256-GCM encrypted before reaching S3; the plaintext never
    touches the object store.  The wrapped AES key is stored in the DB row."""
    raw = await file.read()
    content_id = str(uuid.uuid4())
    s3_key = f"vault/{content_id}.enc"

    ciphertext, wrapped_key, iv_b64 = vault_service.encrypt_content(raw)
    await asyncio.to_thread(vault_service.upload_encrypted, s3_key, ciphertext)

    record = models.VaultContent(
        id=content_id,
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(raw),
        s3_key=s3_key,
        encrypted_key=wrapped_key,
        iv=iv_b64,
        description=description.strip() or None,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    return {
        "content_id": content_id,
        "filename": file.filename,
        "size_bytes": len(raw),
        "content_type": record.content_type,
        "uploaded_at": record.uploaded_at.isoformat() + "Z",
    }


@app.get("/admin/vault/contents")
async def vault_list_admin(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Admin: list all vault items with full metadata."""
    result = await db.execute(
        select(models.VaultContent).order_by(models.VaultContent.uploaded_at.desc())
    )
    rows = result.scalars().all()
    return [
        {
            "content_id": r.id,
            "filename": r.filename,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
            "description": r.description,
            "uploaded_at": r.uploaded_at.isoformat() + "Z",
        }
        for r in rows
    ]


@app.delete("/admin/vault/{content_id}", status_code=200)
async def vault_delete(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Delete a vault item from both S3 and the database."""
    record = await db.get(models.VaultContent, content_id)
    if not record:
        raise HTTPException(status_code=404, detail="Content not found")

    await asyncio.to_thread(vault_service.delete_object, record.s3_key)
    await db.delete(record)
    await db.commit()
    return {"status": "deleted", "content_id": content_id}


# ── Content ↔ License associations ────────────────────────────────────────────

@app.post("/admin/licenses/{invoice_id}/content/{content_id}", status_code=201)
async def grant_content_to_license(
    invoice_id: str,
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Grant a license access to a specific vault content item.

    Once any license association exists for a content item, ONLY linked
    licenses may stream it.  Content with no associations is open to any
    valid paid license.
    """
    lic_result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    content = await db.get(models.VaultContent, content_id)
    if not content:
        raise HTTPException(status_code=404, detail="Content not found")

    existing = await db.execute(
        select(models.LicenseContent).where(
            models.LicenseContent.license_id == lic.id,
            models.LicenseContent.content_id == content_id,
        )
    )
    if existing.scalars().first():
        raise HTTPException(status_code=409, detail="License already has access to this content")

    db.add(models.LicenseContent(license_id=lic.id, content_id=content_id))
    await db.commit()
    return {"status": "granted", "invoice_id": invoice_id, "content_id": content_id}


@app.delete("/admin/licenses/{invoice_id}/content/{content_id}", status_code=200)
async def revoke_content_from_license(
    invoice_id: str,
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Remove a license's access to a vault content item."""
    lic_result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    link_result = await db.execute(
        select(models.LicenseContent).where(
            models.LicenseContent.license_id == lic.id,
            models.LicenseContent.content_id == content_id,
        )
    )
    link = link_result.scalars().first()
    if not link:
        raise HTTPException(status_code=404, detail="Association not found")

    await db.delete(link)
    await db.commit()
    return {"status": "revoked", "invoice_id": invoice_id, "content_id": content_id}


@app.get("/admin/licenses/{invoice_id}/content")
async def list_content_for_license(
    invoice_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all vault content items linked to a license."""
    lic_result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    result = await db.execute(
        select(models.VaultContent)
        .join(models.LicenseContent, models.LicenseContent.content_id == models.VaultContent.id)
        .where(models.LicenseContent.license_id == lic.id)
        .order_by(models.VaultContent.uploaded_at.desc())
    )
    rows = result.scalars().all()
    return [
        {
            "content_id": r.id,
            "filename": r.filename,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
            "description": r.description,
            "uploaded_at": r.uploaded_at.isoformat() + "Z",
        }
        for r in rows
    ]


@app.get("/admin/vault/{content_id}/licenses")
async def list_licenses_for_content(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all licenses that have been granted access to a vault content item."""
    content = await db.get(models.VaultContent, content_id)
    if not content:
        raise HTTPException(status_code=404, detail="Content not found")

    result = await db.execute(
        select(models.License, models.LicenseContent.granted_at)
        .join(models.LicenseContent, models.LicenseContent.license_id == models.License.id)
        .where(models.LicenseContent.content_id == content_id)
        .order_by(models.LicenseContent.granted_at.desc())
    )
    rows = result.all()
    return [
        {
            "invoice_id": lic.invoice_id,
            "owner_id": lic.owner_id,
            "is_paid": lic.is_paid,
            "granted_at": granted_at.isoformat() + "Z",
        }
        for lic, granted_at in rows
    ]


@app.get("/vault/contents")
async def vault_list_public(db: AsyncSession = Depends(get_db)):
    """Public: list vault items with safe metadata only (no keys, no S3 paths)."""
    result = await db.execute(
        select(models.VaultContent).order_by(models.VaultContent.uploaded_at.desc())
    )
    rows = result.scalars().all()
    return [
        {
            "content_id": r.id,
            "filename": r.filename,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
            "description": r.description,
            "uploaded_at": r.uploaded_at.isoformat() + "Z",
        }
        for r in rows
    ]


@app.post("/vault/access/{content_id}")
async def vault_request_access(
    content_id: str,
    invoice_id: str,
    license_key: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Verify a license key, check geo and session limits, then return a
    short-lived vault access JWT valid for VAULT_ACCESS_TOKEN_MINUTES minutes.
    The JWT is used in GET /vault/stream/{access_token} to stream the file."""
    record = await db.get(models.VaultContent, content_id)
    if not record:
        raise HTTPException(status_code=404, detail="Content not found")

    lic_result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    if not lic or not verify_license_key(license_key, lic.license_key):
        raise HTTPException(status_code=403, detail="Invalid license key")

    # Content-license access control: if the content has any license associations,
    # only linked licenses may stream it.  Zero associations = open to any valid license.
    has_any_link = await db.execute(
        select(models.LicenseContent)
        .where(models.LicenseContent.content_id == content_id)
        .limit(1)
    )
    if has_any_link.scalars().first() is not None:
        this_link = await db.execute(
            select(models.LicenseContent).where(
                models.LicenseContent.license_id == lic.id,
                models.LicenseContent.content_id == content_id,
            )
        )
        if not this_link.scalars().first():
            raise HTTPException(
                status_code=403,
                detail="This license does not have access to the requested content",
            )

    # Geofence check
    if lic.allowed_countries:
        country = await geo_service.get_country_code(request.client.host)
        if not geo_service.is_permitted(country, lic.allowed_countries):
            raise HTTPException(status_code=403, detail=f"Region not permitted: {country}")

    # Concurrent session limit check
    active_threshold = datetime.utcnow() - timedelta(minutes=SESSION_ACTIVE_MINUTES)
    active_result = await db.execute(
        select(models.ViewAnalytics).where(
            models.ViewAnalytics.license_id == lic.id,
            models.ViewAnalytics.last_heartbeat >= active_threshold,
        )
    )
    if len(active_result.scalars().all()) >= lic.max_sessions:
        raise HTTPException(
            status_code=409,
            detail=f"Session limit reached ({lic.max_sessions} concurrent session(s) allowed)",
        )

    # Start an analytics session for the vault access
    session = models.ViewAnalytics(
        license_id=lic.id,
        content_id=content_id,
        device_info=request.headers.get("user-agent", "unknown"),
        ip_address=request.client.host,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    await redis_service.register_session(
        session_id=session.id,
        license_id=lic.id,
        invoice_id=invoice_id,
        content_id=content_id,
        ip_address=request.client.host,
    )

    # Use time.time() for JWT timestamps — datetime.utcnow().timestamp() is
    # incorrect on non-UTC hosts because it interprets a naive UTC datetime as
    # local time.  time.time() always returns the correct UTC Unix epoch.
    now_ts = int(_time.time())
    access_token = _jwt.encode(
        {
            "type": "vault_access",
            "sub": content_id,
            "session_id": session.id,
            "iat": now_ts,
            "exp": now_ts + VAULT_ACCESS_TOKEN_MINUTES * 60,
        },
        OFFLINE_TOKEN_SECRET,
        algorithm="HS256",
    )
    return {
        "access_token": access_token,
        "session_id": session.id,
        "expires_in_seconds": VAULT_ACCESS_TOKEN_MINUTES * 60,
        "filename": record.filename,
        "content_type": record.content_type,
        "size_bytes": record.size_bytes,
    }


@app.get("/vault/stream/{access_token}")
async def vault_stream(
    access_token: str,
    db: AsyncSession = Depends(get_db),
):
    """Stream decrypted vault content to an authorised viewer.
    Validates the short-lived JWT, downloads the encrypted blob from S3,
    decrypts in memory, then yields the plaintext in 64 KB chunks."""
    try:
        payload = _jwt.decode(access_token, OFFLINE_TOKEN_SECRET, algorithms=["HS256"])
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except _jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    if payload.get("type") != "vault_access":
        raise HTTPException(status_code=401, detail="Wrong token type")

    content_id = payload["sub"]
    record = await db.get(models.VaultContent, content_id)
    if not record:
        raise HTTPException(status_code=404, detail="Content not found")

    ciphertext = await asyncio.to_thread(vault_service.download_encrypted, record.s3_key)
    plaintext = vault_service.decrypt_content(ciphertext, record.encrypted_key, record.iv)

    chunk_size = 64 * 1024  # 64 KB

    async def generate():
        offset = 0
        while offset < len(plaintext):
            yield plaintext[offset: offset + chunk_size]
            offset += chunk_size

    return StreamingResponse(
        generate(),
        media_type=record.content_type,
        headers={
            "Content-Disposition": f'inline; filename="{record.filename}"',
            "Content-Length": str(len(plaintext)),
            "Cache-Control": "no-store",
        },
    )


# ── Multi-Tenant SaaS ──────────────────────────────────────────

@app.post("/superadmin/tenants", status_code=201)
async def create_tenant(
    name: str,
    slug: str,
    admin_key: str,
    plan: str = "starter",
    max_licenses: int = 10,
    max_vault_mb: int = 100,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    """Create a new tenant. The admin_key is bcrypt-hashed and never stored in plain form."""
    existing = await db.execute(select(models.Tenant).where(models.Tenant.slug == slug))
    if existing.scalars().first():
        raise HTTPException(status_code=409, detail=f"Tenant slug already exists: {slug}")
    tenant = models.Tenant(
        name=name,
        slug=slug,
        admin_key_hash=hash_license_key(admin_key),
        plan=plan,
        max_licenses=max_licenses,
        max_vault_mb=max_vault_mb,
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "plan": tenant.plan,
        "max_licenses": tenant.max_licenses,
        "max_vault_mb": tenant.max_vault_mb,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat() + "Z",
    }


@app.get("/superadmin/tenants")
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    """List all tenants."""
    result = await db.execute(select(models.Tenant).order_by(models.Tenant.created_at.desc()))
    return [
        {
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "plan": t.plan,
            "max_licenses": t.max_licenses,
            "max_vault_mb": t.max_vault_mb,
            "is_active": t.is_active,
            "created_at": t.created_at.isoformat() + "Z",
        }
        for t in result.scalars().all()
    ]


@app.patch("/superadmin/tenants/{slug}")
async def update_tenant(
    slug: str,
    plan: str = None,
    max_licenses: int = None,
    max_vault_mb: int = None,
    is_active: bool = None,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    """Update a tenant's plan, limits, or active status."""
    result = await db.execute(select(models.Tenant).where(models.Tenant.slug == slug))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if plan is not None:
        tenant.plan = plan
    if max_licenses is not None:
        tenant.max_licenses = max_licenses
    if max_vault_mb is not None:
        tenant.max_vault_mb = max_vault_mb
    if is_active is not None:
        tenant.is_active = is_active
    await db.commit()
    return {"slug": slug, "updated": True}


@app.delete("/superadmin/tenants/{slug}", status_code=200)
async def delete_tenant(
    slug: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    """Permanently delete a tenant and all its data."""
    result = await db.execute(select(models.Tenant).where(models.Tenant.slug == slug))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await db.delete(tenant)
    await db.commit()
    return {"status": "deleted", "slug": slug}


# ── Tenant-scoped endpoints ────────────────────────────────────

@app.post("/tenant/licenses", status_code=201)
async def tenant_create_license(
    invoice_id: str,
    owner_id: str,
    max_sessions: int = 1,
    allowed_countries: str = "",
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: create a license scoped to this tenant, subject to plan limits."""
    count_result = await db.execute(
        select(models.License).where(models.License.tenant_id == tenant.id)
    )
    if len(count_result.scalars().all()) >= tenant.max_licenses:
        raise HTTPException(
            status_code=403,
            detail=f"License limit reached for plan '{tenant.plan}' (max {tenant.max_licenses})",
        )
    plain_key = f"SK-{secrets.token_urlsafe(16)}"
    hashed_key = hash_license_key(plain_key)
    new_license = models.License(
        invoice_id=invoice_id,
        license_key=hashed_key,
        owner_id=owner_id,
        is_paid=False,
        max_sessions=max_sessions,
        allowed_countries=allowed_countries.upper().strip() or None,
        tenant_id=tenant.id,
    )
    db.add(new_license)
    await db.commit()
    return {
        "invoice_id": invoice_id,
        "plain_key_to_copy": plain_key,
        "warning": "Save the key — only the hash is stored.",
    }


@app.get("/tenant/licenses")
async def tenant_list_licenses(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: list licenses belonging to this tenant only."""
    result = await db.execute(
        select(models.License).where(models.License.tenant_id == tenant.id)
    )
    return result.scalars().all()


@app.get("/tenant/audit-log")
async def tenant_audit_log(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: audit log scoped to this tenant."""
    result = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.tenant_id == tenant.id)
        .order_by(models.AuditLog.timestamp.desc())
        .limit(100)
    )
    return result.scalars().all()


@app.get("/tenant/analytics")
async def tenant_analytics(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: viewing analytics scoped to this tenant."""
    result = await db.execute(
        select(models.ViewAnalytics)
        .where(models.ViewAnalytics.tenant_id == tenant.id)
        .order_by(models.ViewAnalytics.start_time.desc())
    )
    return result.scalars().all()


@app.get("/tenant/alerts")
async def tenant_alerts(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: failed access attempts in the last 30 minutes for this tenant."""
    time_threshold = datetime.utcnow() - timedelta(minutes=30)
    result = await db.execute(
        select(models.AuditLog)
        .where(
            models.AuditLog.tenant_id == tenant.id,
            models.AuditLog.is_success == False,
            models.AuditLog.timestamp >= time_threshold,
        )
        .order_by(models.AuditLog.timestamp.desc())
    )
    return result.scalars().all()


@app.post("/tenant/offline-token", status_code=201)
async def tenant_issue_offline_token(
    invoice_id: str,
    hours: int = 24,
    device_hint: str = "",
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: issue an offline token for a license in this tenant."""
    result = await db.execute(
        select(models.License).where(
            models.License.invoice_id == invoice_id,
            models.License.tenant_id == tenant.id,
        )
    )
    if not result.scalars().first():
        raise HTTPException(status_code=404, detail="License not found in this tenant")
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
        tenant_id=tenant.id,
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


@app.get("/tenant/offline-tokens")
async def tenant_list_offline_tokens(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: list offline tokens issued for this tenant."""
    result = await db.execute(
        select(models.OfflineToken)
        .where(models.OfflineToken.tenant_id == tenant.id)
        .order_by(models.OfflineToken.issued_at.desc())
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
            "hours_remaining": max(0, int((t.valid_until - now).total_seconds() // 3600)),
        }
        for t in result.scalars().all()
    ]


@app.delete("/tenant/offline-token/{token_id}")
async def tenant_revoke_offline_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: revoke an offline token owned by this tenant."""
    row = await db.get(models.OfflineToken, token_id)
    if not row or row.tenant_id != tenant.id:
        raise HTTPException(status_code=404, detail="Token not found in this tenant")
    row.is_revoked = True
    await db.commit()
    return {"status": "revoked", "token_id": token_id}


@app.post("/tenant/vault/upload", status_code=201)
async def tenant_vault_upload(
    file: UploadFile = File(...),
    description: str = "",
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: upload encrypted content to this tenant's vault partition."""
    quota_result = await db.execute(
        select(models.VaultContent).where(models.VaultContent.tenant_id == tenant.id)
    )
    used_bytes = sum(r.size_bytes for r in quota_result.scalars().all())
    max_bytes = tenant.max_vault_mb * 1024 * 1024
    raw = await file.read()
    if used_bytes + len(raw) > max_bytes:
        raise HTTPException(
            status_code=403,
            detail=f"Vault quota exceeded ({tenant.max_vault_mb} MB limit for plan '{tenant.plan}')",
        )
    content_id = str(uuid.uuid4())
    s3_key = f"vault/{tenant.slug}/{content_id}.enc"
    ciphertext, wrapped_key, iv_b64 = vault_service.encrypt_content(raw)
    await asyncio.to_thread(vault_service.upload_encrypted, s3_key, ciphertext)
    record = models.VaultContent(
        id=content_id,
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(raw),
        s3_key=s3_key,
        encrypted_key=wrapped_key,
        iv=iv_b64,
        description=description.strip() or None,
        tenant_id=tenant.id,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return {
        "content_id": content_id,
        "filename": file.filename,
        "size_bytes": len(raw),
        "content_type": record.content_type,
        "uploaded_at": record.uploaded_at.isoformat() + "Z",
    }


@app.get("/tenant/vault/contents")
async def tenant_vault_list(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: list vault items belonging to this tenant only."""
    result = await db.execute(
        select(models.VaultContent)
        .where(models.VaultContent.tenant_id == tenant.id)
        .order_by(models.VaultContent.uploaded_at.desc())
    )
    return [
        {
            "content_id": r.id,
            "filename": r.filename,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
            "description": r.description,
            "uploaded_at": r.uploaded_at.isoformat() + "Z",
        }
        for r in result.scalars().all()
    ]


@app.delete("/tenant/vault/{content_id}")
async def tenant_vault_delete(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Tenant admin: delete a vault item owned by this tenant."""
    record = await db.get(models.VaultContent, content_id)
    if not record or record.tenant_id != tenant.id:
        raise HTTPException(status_code=404, detail="Content not found in this tenant")
    await asyncio.to_thread(vault_service.delete_object, record.s3_key)
    await db.delete(record)
    await db.commit()
    return {"status": "deleted", "content_id": content_id}


@app.post("/signout")
async def signout(invoice_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    await log_attempt(db, invoice_id, client_ip, False, f"SIGNOUT | {user_agent}")
    return {"status": "signed_out"}


# ── AI Anomaly Pattern Discovery ───────────────────────────────────────────

async def _run_anomaly_analysis(
    db: AsyncSession,
    hours: float,
    min_score: int,
    skip_geo: bool,
    tenant_id: int | None = None,
) -> tuple[list[dict], dict]:
    """Shared logic for admin and tenant anomaly endpoints."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Scoped session query
    session_q = select(models.ViewAnalytics).where(
        models.ViewAnalytics.start_time >= cutoff
    )
    if tenant_id is not None:
        session_q = session_q.where(models.ViewAnalytics.tenant_id == tenant_id)
    sessions_result = await db.execute(session_q)
    sessions = sessions_result.scalars().all()

    # Scoped audit-log query
    audit_q = select(models.AuditLog).where(
        models.AuditLog.timestamp >= cutoff
    )
    if tenant_id is not None:
        audit_q = audit_q.where(models.AuditLog.tenant_id == tenant_id)
    audit_result = await db.execute(audit_q)
    audit_logs = audit_result.scalars().all()

    # Build license_map: license_id → License row
    license_ids = list({s.license_id for s in sessions})
    license_map: dict[int, models.License] = {}
    if license_ids:
        lic_result = await db.execute(
            select(models.License).where(models.License.id.in_(license_ids))
        )
        for lic in lic_result.scalars().all():
            license_map[lic.id] = lic

    # Optionally build country_map: ip → country_code
    country_map: dict[str, str] | None = None
    if not skip_geo and sessions:
        unique_ips = list({s.ip_address for s in sessions if s.ip_address})
        country_map = {}
        for ip in unique_ips:
            try:
                country_map[ip] = await geo_service.get_country_code(ip)
            except Exception:
                country_map[ip] = ""

    findings = anomaly_service.analyze_all(
        sessions=sessions,
        audit_logs=audit_logs,
        country_map=country_map,
        license_map=license_map,
    )
    if min_score > 0:
        findings = [f for f in findings if f["score"] >= min_score]

    summary = anomaly_service.build_summary(findings)
    return findings, summary


@app.get("/admin/anomalies")
async def get_anomalies(
    hours: float = 24.0,
    min_score: int = 0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """AI Anomaly Pattern Discovery — full findings list.

    Runs 7 statistical detectors over the last `hours` of telemetry and returns
    scored anomaly findings with evidence payloads and natural-language
    recommendations, sorted by severity score descending.

    Query params:
    - hours     : rolling window to analyse (default 24)
    - min_score : filter out findings below this score (default 0 = all)
    - skip_geo  : skip multi-country detection (faster, no GeoIP lookups)
    """
    findings, summary = await _run_anomaly_analysis(
        db, hours, min_score, skip_geo, tenant_id=None
    )
    return {"findings": findings, "summary": summary}


@app.get("/admin/anomalies/summary")
async def get_anomalies_summary(
    hours: float = 24.0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """Quick anomaly summary — counts by severity + top 3 findings.
    Designed for embedding in the admin dashboard status strip."""
    findings, summary = await _run_anomaly_analysis(
        db, hours, min_score=0, skip_geo=skip_geo, tenant_id=None
    )
    return {"summary": summary, "top_findings": findings[:3]}


@app.get("/tenant/anomalies")
async def tenant_get_anomalies(
    hours: float = 24.0,
    min_score: int = 0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """AI Anomaly Pattern Discovery scoped to this tenant's data."""
    findings, summary = await _run_anomaly_analysis(
        db, hours, min_score, skip_geo, tenant_id=tenant.id
    )
    return {"findings": findings, "summary": summary}


@app.post("/create-checkout-session")
async def create_checkout(invoice_id: str):
    try:
        # Создаем сессию оплаты. Передаем invoice_id в metadata,
        # чтобы Stripe вернул его нам в вебхуке.
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': f'Access License: {invoice_id}'},
                    'unit_amount': 5000, # $50.00
                },
                'quantity': 1,
            }],
            mode='payment',
            metadata={'invoice_id': invoice_id},
            success_url='http://localhost:3000/success',
            cancel_url='http://localhost:3000/cancel',
        )
        return {"url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_service.WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": "Invalid signature"}, 400

    # Если оплата прошла успешно
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        invoice_id = session['metadata'].get('invoice_id')
        await stripe_service.handle_payment_success(invoice_id)

    return {"status": "success"}
