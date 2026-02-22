"""
Content Vault routes:
  POST   /admin/vault/upload
  GET    /admin/vault/contents
  DELETE /admin/vault/{content_id}
  POST   /admin/licenses/{invoice_id}/content/{content_id}
  DELETE /admin/licenses/{invoice_id}/content/{content_id}
  GET    /admin/licenses/{invoice_id}/content
  GET    /admin/vault/{content_id}/licenses
  GET    /vault/contents
  POST   /vault/access/{content_id}
  GET    /vault/stream/{access_token}
"""
import asyncio
import re
import uuid
import time as _time
import jwt as _jwt
from datetime import datetime, timedelta
from urllib.parse import quote as _url_quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, require_admin
from auth_utils import verify_license_key
from schemas import VaultAccessRequest
import models
import geo_service
import redis_service
import vault_service
from config import (
    VAULT_TOKEN_SECRET,
    VAULT_ACCESS_TOKEN_MINUTES,
    SESSION_ACTIVE_MINUTES,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_MB,
)

router = APIRouter()


# ── Admin vault management ─────────────────────────────────────────────────────

@router.post("/admin/vault/upload", status_code=201)
async def vault_upload(
    file: UploadFile = File(...),
    description: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {MAX_UPLOAD_MB} MB per upload)",
        )
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


@router.get("/admin/vault/contents")
async def vault_list_admin(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    result = await db.execute(
        select(models.VaultContent)
        .order_by(models.VaultContent.uploaded_at.desc())
        .offset(skip)
        .limit(limit)
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


@router.delete("/admin/vault/{content_id}", status_code=200)
async def vault_delete(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    record = await db.get(models.VaultContent, content_id)
    if not record:
        raise HTTPException(status_code=404, detail="Content not found")
    await asyncio.to_thread(vault_service.delete_object, record.s3_key)
    await db.delete(record)
    await db.commit()
    return {"status": "deleted", "content_id": content_id}


# ── Content ↔ License associations ────────────────────────────────────────────

@router.post("/admin/licenses/{invoice_id}/content/{content_id}", status_code=201)
async def grant_content_to_license(
    invoice_id: str,
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
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


@router.delete("/admin/licenses/{invoice_id}/content/{content_id}", status_code=200)
async def revoke_content_from_license(
    invoice_id: str,
    content_id: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
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


@router.get("/admin/licenses/{invoice_id}/content")
async def list_content_for_license(
    invoice_id: str,
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
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
        .offset(skip)
        .limit(limit)
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


@router.get("/admin/vault/{content_id}/licenses")
async def list_licenses_for_content(
    content_id: str,
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    content = await db.get(models.VaultContent, content_id)
    if not content:
        raise HTTPException(status_code=404, detail="Content not found")

    result = await db.execute(
        select(models.License, models.LicenseContent.granted_at)
        .join(models.LicenseContent, models.LicenseContent.license_id == models.License.id)
        .where(models.LicenseContent.content_id == content_id)
        .order_by(models.LicenseContent.granted_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return [
        {
            "invoice_id": lic.invoice_id,
            "owner_id": lic.owner_id,
            "is_paid": lic.is_paid,
            "granted_at": granted_at.isoformat() + "Z",
        }
        for lic, granted_at in result.all()
    ]


# ── Public vault access ────────────────────────────────────────────────────────

@router.get("/vault/contents")
async def vault_list_public(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.VaultContent)
        .order_by(models.VaultContent.uploaded_at.desc())
        .offset(skip)
        .limit(limit)
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


@router.post("/vault/access/{content_id}")
async def vault_request_access(
    content_id: str,
    body: VaultAccessRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Request a short-lived vault access token.

    Credentials are passed in the JSON body (not query parameters) to prevent
    the license key from appearing in server logs, CDN logs, or browser history.
    """
    invoice_id = body.invoice_id
    license_key = body.license_key

    record = await db.get(models.VaultContent, content_id)
    if not record:
        raise HTTPException(status_code=404, detail="Content not found")

    lic_result = await db.execute(
        select(models.License).where(models.License.invoice_id == invoice_id)
    )
    lic = lic_result.scalars().first()
    if not lic or not verify_license_key(license_key, lic.license_key):
        raise HTTPException(status_code=403, detail="Invalid license key")
    if not lic.is_paid:
        raise HTTPException(status_code=402, detail="License not activated: payment required")

    # Content-license access control: open-by-default model
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

    # Concurrent session limit
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

    now_ts = int(_time.time())
    access_token = _jwt.encode(
        {
            "type": "vault_access",
            "sub": content_id,
            "session_id": session.id,
            "iat": now_ts,
            "exp": now_ts + VAULT_ACCESS_TOKEN_MINUTES * 60,
        },
        VAULT_TOKEN_SECRET,
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


@router.get("/vault/stream/{access_token}")
async def vault_stream(
    access_token: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = _jwt.decode(access_token, VAULT_TOKEN_SECRET, algorithms=["HS256"])
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

    chunk_size = 64 * 1024

    async def generate():
        offset = 0
        while offset < len(plaintext):
            yield plaintext[offset: offset + chunk_size]
            offset += chunk_size

    # Build a safe Content-Disposition header.
    # The filename* (RFC 5987) form handles arbitrary Unicode/special chars without
    # header-injection risk.  The plain filename= fallback uses only ASCII-safe chars.
    raw_name = record.filename or "file"
    ascii_name = re.sub(r'[^\w.\-]', '_', raw_name)          # strip non-ASCII / control chars
    encoded_name = _url_quote(raw_name, safe='')               # RFC 5987 percent-encoding
    content_disposition = (
        f"inline; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded_name}"
    )

    return StreamingResponse(
        generate(),
        media_type=record.content_type,
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(plaintext)),
            "Cache-Control": "no-store",
        },
    )
