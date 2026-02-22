"""
Super-admin routes (require X-Super-Admin-Key):
  POST   /superadmin/tenants
  GET    /superadmin/tenants
  PATCH  /superadmin/tenants/{slug}
  DELETE /superadmin/tenants/{slug}
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, require_super_admin
from auth_utils import hash_license_key
from rate_limit import limiter, SUPERADMIN_LIMIT
import models

router = APIRouter()


@router.post("/superadmin/tenants", status_code=201)
@limiter.limit(SUPERADMIN_LIMIT)
async def create_tenant(
    request: Request,
    name: str,
    slug: str,
    admin_key: str,
    plan: str = "starter",
    max_licenses: int = Query(default=10, ge=1, le=100_000),
    max_vault_mb: int = Query(default=100, ge=1, le=51_200),   # max 50 GB
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    existing = await db.execute(
        select(models.Tenant).where(models.Tenant.slug == slug)
    )
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


@router.get("/superadmin/tenants")
async def list_tenants(
    skip: int = 0,
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    result = await db.execute(
        select(models.Tenant)
        .order_by(models.Tenant.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
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


@router.patch("/superadmin/tenants/{slug}")
async def update_tenant(
    slug: str,
    plan: str = None,
    max_licenses: int = Query(default=None, ge=1, le=100_000),
    max_vault_mb: int = Query(default=None, ge=1, le=51_200),
    is_active: bool = None,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    result = await db.execute(
        select(models.Tenant).where(models.Tenant.slug == slug)
    )
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


@router.delete("/superadmin/tenants/{slug}", status_code=200)
async def delete_tenant(
    slug: str,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    result = await db.execute(
        select(models.Tenant).where(models.Tenant.slug == slug)
    )
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await db.delete(tenant)
    await db.commit()
    return {"status": "deleted", "slug": slug}
