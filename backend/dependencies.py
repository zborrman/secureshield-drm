"""
Shared FastAPI dependencies and utility functions used across all routers.
"""
import hmac as _hmac
import jwt as _jwt
from fastapi import Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import SessionLocal
from auth_utils import verify_license_key
import models
import redis_service as _redis_service
from config import ADMIN_API_KEY, ADMIN_SESSION_SECRET, SUPER_ADMIN_KEY

_TENANT_CACHE_TTL = 300  # seconds — 5-minute tenant config cache


# ── Database ───────────────────────────────────────────────────────────────────

async def get_db():
    async with SessionLocal() as session:
        yield session


# ── Auth dependencies ──────────────────────────────────────────────────────────

def _admin_session_secret() -> str:
    """Return the HS256 signing secret for admin session JWTs.

    If ADMIN_SESSION_SECRET is explicitly set (recommended for production), it is
    used directly.  Otherwise we derive a 64-byte hex digest from ADMIN_API_KEY
    so the secret is always ≥ 32 bytes — eliminating PyJWT's InsecureKeyLengthWarning.
    """
    if ADMIN_SESSION_SECRET:
        return ADMIN_SESSION_SECRET
    import hashlib
    return hashlib.sha256((ADMIN_API_KEY + "-admin-session").encode()).hexdigest()


async def require_admin(
    authorization: str = Header(default=""),
    x_admin_key: str = Header(default=""),
):
    """FastAPI dependency: accepts either
    - ``Authorization: Bearer <admin-session-jwt>`` (issued by POST /admin/login), or
    - ``X-Admin-Key: <raw-api-key>`` (legacy / direct access).
    """
    # ── Option 1: short-lived admin session JWT ──────────────────────────────
    if authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            _jwt.decode(token, _admin_session_secret(), algorithms=["HS256"])
            return  # valid session JWT
        except _jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Admin session expired — please log in again",
            )
        except _jwt.InvalidTokenError:
            raise HTTPException(
                status_code=401,
                detail="Invalid admin session token",
            )

    # ── Option 2: raw API key (legacy / backward-compatible) ─────────────────
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
    """FastAPI dependency: resolves and validates the current tenant from headers.

    Tenant config (id, slug, plan, admin_key_hash) is cached in Redis for
    _TENANT_CACHE_TTL seconds to reduce DB round-trips on tenant-scoped endpoints.
    The bcrypt key-verify step always runs (cache only skips the DB SELECT).
    Cache is invalidated by superadmin PATCH/DELETE operations.
    """
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="Missing X-Tenant-ID header")

    # ── Try Redis cache first ────────────────────────────────────────────────
    _cache_key = f"tenant:{x_tenant_id}"
    cached = await _redis_service.cache_get(_cache_key)
    if cached:
        # Re-use cached admin_key_hash to avoid DB round-trip
        if not cached.get("is_active", True):
            raise HTTPException(status_code=403, detail="Tenant account is deactivated")
        if not verify_license_key(x_admin_key, cached["admin_key_hash"]):
            raise HTTPException(status_code=401, detail="Invalid tenant admin key")
        # Reconstruct a lightweight namespace object the routers can read
        tenant = models.Tenant()
        tenant.id = int(cached["id"])
        tenant.slug = cached["slug"]
        tenant.admin_key_hash = cached["admin_key_hash"]
        tenant.plan = cached.get("plan", "starter")
        tenant.max_licenses = cached.get("max_licenses", 100)
        tenant.is_active = cached.get("is_active", True)
        return tenant

    # ── Cache miss — query DB ────────────────────────────────────────────────
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

    # Populate cache for subsequent requests
    await _redis_service.cache_set(_cache_key, {
        "id": str(tenant.id),
        "slug": tenant.slug,
        "admin_key_hash": tenant.admin_key_hash,
        "plan": tenant.plan,
        "max_licenses": tenant.max_licenses,
        "is_active": tenant.is_active,
    }, ttl=_TENANT_CACHE_TTL)

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
