"""
Public authentication and analytics routes:
  POST /verify-license
  POST /signout
  POST /verify-offline-token
  POST /create-checkout-session
  POST /webhook/stripe
  POST /analytics/start
  POST /analytics/heartbeat/{session_id}
"""
import hmac as _hmac
import stripe
import jwt as _jwt
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, log_attempt
from auth_utils import verify_license_key
from watermark_service import generate_user_fingerprint
import stripe_service
import models
import geo_service
import redis_service
from config import (
    BRUTE_FORCE_WINDOW_MINUTES,
    BRUTE_FORCE_MAX_FAILS,
    OFFLINE_TOKEN_SECRET,
    SESSION_ACTIVE_MINUTES,
    BOT_THRESHOLD_MS,
)
from rate_limit import limiter, ANALYTICS_LIMIT

router = APIRouter()


@router.post("/verify-license")
async def verify(
    invoice_id: str,
    input_key: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")

    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    license_record = result.scalars().first()

    # Brute-force protection: sliding window — only count failures within the last N minutes
    brute_window = datetime.utcnow() - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    recent_fails = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.ip_address == client_ip)
        .where(models.AuditLog.is_success == False)
        .where(models.AuditLog.timestamp >= brute_window)
        .limit(BRUTE_FORCE_MAX_FAILS)
    )
    if len(recent_fails.all()) >= BRUTE_FORCE_MAX_FAILS:
        await log_attempt(db, invoice_id, client_ip, False, user_agent)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {BRUTE_FORCE_WINDOW_MINUTES} minutes.",
            headers={"Retry-After": str(BRUTE_FORCE_WINDOW_MINUTES * 60)},
        )

    # Geofence check: reject IPs outside the license's allowed regions
    if license_record and license_record.allowed_countries:
        country = await geo_service.get_country_code(client_ip)
        if not geo_service.is_permitted(country, license_record.allowed_countries):
            await log_attempt(
                db, invoice_id, client_ip, False,
                f"GEO_BLOCKED:{country} | {user_agent}",
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: your region ({country}) is not permitted for this license",
            )

    success = False
    if license_record and verify_license_key(input_key, license_record.license_key):
        if not license_record.is_paid:
            await log_attempt(db, invoice_id, client_ip, False, user_agent)
            raise HTTPException(status_code=402, detail="License not activated: payment required")
        success = True

    await log_attempt(db, invoice_id, client_ip, success, user_agent)

    if not success:
        raise HTTPException(status_code=403, detail="Invalid Key")

    return {"status": "success", "fingerprint": generate_user_fingerprint(license_record.owner_id)}


@router.post("/signout")
async def signout(invoice_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    await log_attempt(db, invoice_id, client_ip, False, f"SIGNOUT | {user_agent}")
    return {"status": "signed_out"}


@router.post("/verify-offline-token")
async def verify_offline_token(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Validate an offline JWT — checks signature, expiry, and revocation status."""
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

    hours_remaining = max(
        0, int((row.valid_until - datetime.utcnow()).total_seconds() // 3600)
    )
    return {
        "valid": True,
        "invoice_id": payload["sub"],
        "hours_remaining": hours_remaining,
        "device_hint": row.device_hint,
    }


@router.post("/create-checkout-session")
async def create_checkout(invoice_id: str):
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"Access License: {invoice_id}"},
                    "unit_amount": 5000,  # $50.00
                },
                "quantity": 1,
            }],
            mode="payment",
            metadata={"invoice_id": invoice_id},
            success_url="http://localhost:3000/success",
            cancel_url="http://localhost:3000/cancel",
        )
        return {"url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_service.WEBHOOK_SECRET
        )
    except Exception:
        return {"error": "Invalid signature"}, 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        invoice_id = session["metadata"].get("invoice_id")
        await stripe_service.handle_payment_success(invoice_id)

    return {"status": "success"}


# ── Analytics (public-facing, called by the viewer) ──────────────────────────

@router.post("/analytics/start", status_code=201)
@limiter.limit(ANALYTICS_LIMIT)
async def analytics_start(
    invoice_id: str,
    content_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called once when a user unlocks content. Returns session_id for heartbeats."""
    result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    license_record = result.scalars().first()
    if not license_record:
        raise HTTPException(status_code=404, detail="License not found")

    # Geofence check (before is_paid so blocked regions see 403, not 402)
    if license_record.allowed_countries:
        country = await geo_service.get_country_code(request.client.host)
        if not geo_service.is_permitted(country, license_record.allowed_countries):
            raise HTTPException(
                status_code=403,
                detail=f"Region not permitted: {country}",
            )

    if not license_record.is_paid:
        raise HTTPException(status_code=402, detail="License not activated: payment required")

    # Enforce concurrent session limit
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

    await redis_service.register_session(
        session_id=session.id,
        license_id=license_record.id,
        invoice_id=invoice_id,
        content_id=content_id,
        ip_address=request.client.host,
    )
    return {"session_id": session.id}


@router.post("/analytics/heartbeat/{session_id}")
async def analytics_heartbeat(
    session_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Called every 30s by the viewer to accumulate duration_seconds.

    On the first heartbeat, checks timing: if < BOT_THRESHOLD_MS after session
    start the session is flagged as a bot suspect.

    Real-time revocation: if an admin revoked this session, returns
    {"revoked": true, "action": "stop"} and the client must cease playback.
    """
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

    is_first_heartbeat = view_session.duration_seconds == 0
    if is_first_heartbeat:
        ms_since_start = (now - view_session.start_time).total_seconds() * 1000
        if ms_since_start < BOT_THRESHOLD_MS:
            view_session.is_bot_suspect = True

    view_session.last_heartbeat = now
    view_session.duration_seconds += delta
    await db.commit()

    await redis_service.refresh_session(session_id)
    return {
        "duration_seconds": view_session.duration_seconds,
        "suspicious": view_session.is_bot_suspect,
        "revoked": False,
    }
