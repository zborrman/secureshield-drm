"""
Tenant-scoped routes (require X-Tenant-ID + X-Admin-Key bcrypt-verified):
  POST   /tenant/licenses
  GET    /tenant/licenses
  GET    /tenant/audit-log
  GET    /tenant/analytics
  GET    /tenant/alerts
  POST   /tenant/offline-token
  GET    /tenant/offline-tokens
  DELETE /tenant/offline-token/{token_id}
  POST   /tenant/vault/upload
  GET    /tenant/vault/contents
  DELETE /tenant/vault/{content_id}
  GET    /tenant/anomalies
"""
import uuid
import asyncio
import secrets
import jwt as _jwt
from datetime import datetime, timedelta
import time as _time

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, get_current_tenant
from auth_utils import hash_license_key
import models
import vault_service
from config import OFFLINE_TOKEN_SECRET, MAX_UPLOAD_BYTES, MAX_UPLOAD_MB, ALLOWED_VAULT_MIME
from rate_limit import limiter, TENANT_WRITE_LIMIT
from schemas import LicenseCreatedResponse, OfflineTokenIssued, VaultUploadResponse
import anomaly_service

router = APIRouter()


# ── Licenses ────────────────────────────────────────────────────────────────

@router.post("/tenant/licenses", status_code=201, response_model=LicenseCreatedResponse)
@limiter.limit(TENANT_WRITE_LIMIT)
async def tenant_create_license(
    request: Request,
    invoice_id: str = Query(max_length=128),
    owner_id: str = Query(max_length=128),
    max_sessions: int = Query(default=1, ge=1, le=100),
    allowed_countries: str = Query(default="", max_length=512),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Create a license scoped to this tenant, subject to plan limits."""
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


@router.get("/tenant/licenses")
async def tenant_list_licenses(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """List licenses belonging to this tenant only."""
    result = await db.execute(
        select(models.License)
        .where(models.License.tenant_id == tenant.id)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


# ── Audit log / analytics / alerts ──────────────────────────────────────────

@router.get("/tenant/audit-log")
async def tenant_audit_log(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Audit log scoped to this tenant."""
    result = await db.execute(
        select(models.AuditLog)
        .where(models.AuditLog.tenant_id == tenant.id)
        .order_by(models.AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/tenant/analytics")
async def tenant_analytics(
    skip: int = 0,
    limit: int = Query(default=50, le=1000),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Viewing analytics scoped to this tenant."""
    result = await db.execute(
        select(models.ViewAnalytics)
        .where(models.ViewAnalytics.tenant_id == tenant.id)
        .order_by(models.ViewAnalytics.start_time.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/tenant/alerts")
async def tenant_alerts(
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Failed access attempts in the last 30 minutes for this tenant."""
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


# ── Offline tokens ───────────────────────────────────────────────────────────

@router.post("/tenant/offline-token", status_code=201, response_model=OfflineTokenIssued)
async def tenant_issue_offline_token(
    invoice_id: str = Query(max_length=128),
    hours: int = Query(default=24, ge=1, le=168),
    device_hint: str = Query(default="", max_length=256),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Issue an offline token for a license in this tenant."""
    result = await db.execute(
        select(models.License).where(
            models.License.invoice_id == invoice_id,
            models.License.tenant_id == tenant.id,
        )
    )
    if not result.scalars().first():
        raise HTTPException(status_code=404, detail="License not found in this tenant")
    hours = max(1, min(hours, 168))  # cap at 7 days
    token_id = str(uuid.uuid4())
    now = _time.time()
    payload = {
        "sub": invoice_id,
        "jti": token_id,
        "iat": int(now),
        "exp": int(now) + hours * 3600,
        "type": "offline",
        "max_offline_hours": hours,
    }
    jwt_token = _jwt.encode(payload, OFFLINE_TOKEN_SECRET, algorithm="HS256")
    valid_until = datetime.utcfromtimestamp(payload["exp"])
    db.add(models.OfflineToken(
        id=token_id,
        invoice_id=invoice_id,
        issued_at=datetime.utcfromtimestamp(now),
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


@router.get("/tenant/offline-tokens")
async def tenant_list_offline_tokens(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """List offline tokens issued for this tenant."""
    result = await db.execute(
        select(models.OfflineToken)
        .where(models.OfflineToken.tenant_id == tenant.id)
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
            "hours_remaining": max(0, int((t.valid_until - now).total_seconds() // 3600)),
        }
        for t in result.scalars().all()
    ]


@router.delete("/tenant/offline-token/{token_id}")
async def tenant_revoke_offline_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Revoke an offline token owned by this tenant."""
    row = await db.get(models.OfflineToken, token_id)
    if not row or row.tenant_id != tenant.id:
        raise HTTPException(status_code=404, detail="Token not found in this tenant")
    row.is_revoked = True
    await db.commit()
    return {"status": "revoked", "token_id": token_id}


# ── Vault ────────────────────────────────────────────────────────────────────

@router.post("/tenant/vault/upload", status_code=201, response_model=VaultUploadResponse)
async def tenant_vault_upload(
    file: UploadFile = File(...),
    description: str = "",
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Upload encrypted content to this tenant's vault partition."""
    # Enforce hard size cap before reading the full file body
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {MAX_UPLOAD_MB} MB per upload)",
        )
    # Tenant uploads are restricted to known safe MIME types
    content_type = (file.content_type or "application/octet-stream").split(";")[0].strip()
    if content_type not in ALLOWED_VAULT_MIME:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported media type: {content_type}",
        )
    quota_result = await db.execute(
        select(models.VaultContent).where(models.VaultContent.tenant_id == tenant.id)
    )
    used_bytes = sum(r.size_bytes for r in quota_result.scalars().all())
    max_bytes = tenant.max_vault_mb * 1024 * 1024
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


@router.get("/tenant/vault/contents")
async def tenant_vault_list(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """List vault items belonging to this tenant only."""
    result = await db.execute(
        select(models.VaultContent)
        .where(models.VaultContent.tenant_id == tenant.id)
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


@router.delete("/tenant/vault/{content_id}")
async def tenant_vault_delete(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """Delete a vault item owned by this tenant."""
    record = await db.get(models.VaultContent, content_id)
    if not record or record.tenant_id != tenant.id:
        raise HTTPException(status_code=404, detail="Content not found in this tenant")
    await asyncio.to_thread(vault_service.delete_object, record.s3_key)
    await db.delete(record)
    await db.commit()
    return {"status": "deleted", "content_id": content_id}


# ── Anomalies ────────────────────────────────────────────────────────────────

@router.get("/tenant/anomalies")
async def tenant_get_anomalies(
    hours: float = 24.0,
    min_score: int = 0,
    skip_geo: bool = False,
    db: AsyncSession = Depends(get_db),
    tenant: models.Tenant = Depends(get_current_tenant),
):
    """AI Anomaly Pattern Discovery scoped to this tenant's data."""
    findings, summary = await anomaly_service.run_anomaly_analysis(
        db, hours, min_score, skip_geo, tenant_id=tenant.id
    )
    return {"findings": findings, "summary": summary}
