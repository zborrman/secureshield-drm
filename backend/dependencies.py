"""
Shared FastAPI dependencies and utility functions used across all routers.
"""
import hmac as _hmac
from fastapi import Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import SessionLocal
from auth_utils import verify_license_key
import models
from config import ADMIN_API_KEY, SUPER_ADMIN_KEY


# ── Database ───────────────────────────────────────────────────────────────────

async def get_db():
    async with SessionLocal() as session:
        yield session


# ── Auth dependencies ──────────────────────────────────────────────────────────

async def require_admin(x_admin_key: str = Header(default="")):
    """FastAPI dependency: verifies X-Admin-Key header via timing-safe comparison."""
    if not ADMIN_API_KEY or not _hmac.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing X-Admin-Key",
        )


async def require_super_admin(x_super_admin_key: str = Header(default="")):
    """FastAPI dependency: verifies X-Super-Admin-Key header via timing-safe comparison."""
    if not SUPER_ADMIN_KEY or not _hmac.compare_digest(x_super_admin_key, SUPER_ADMIN_KEY):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing X-Super-Admin-Key",
        )


async def get_current_tenant(
    x_tenant_id: str = Header(default=""),
    x_admin_key: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> models.Tenant:
    """FastAPI dependency: resolves and validates the current tenant from headers."""
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


# ── Shared utility ─────────────────────────────────────────────────────────────

async def log_attempt(
    db: AsyncSession,
    invoice_id: str,
    ip: str,
    success: bool,
    ua: str,
    tenant_id: int = None,
) -> None:
    """Append an audit-log row. Commits immediately so the row is persisted
    even if the request later raises an HTTPException."""
    new_log = models.AuditLog(
        invoice_id=invoice_id,
        ip_address=ip,
        is_success=success,
        user_agent=ua,
        tenant_id=tenant_id,
    )
    db.add(new_log)
    await db.commit()
