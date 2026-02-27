"""
Super-admin routes (require X-Super-Admin-Key):
  POST   /superadmin/tenants
  GET    /superadmin/tenants
  PATCH  /superadmin/tenants/{slug}
  DELETE /superadmin/tenants/{slug}
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from dependencies import get_db, require_super_admin
from auth_utils import hash_license_key
from rate_limit import limiter, SUPERADMIN_LIMIT
import models
import redis_service

router = APIRouter()


async def _superadmin_audit(
    db: AsyncSession,
    request: Request,
    action: str,
    target: str,
    details: dict,
) -> None:
    """Write an AuditLog entry for a super-admin mutating action.

    Uses invoice_id=None and encodes action + details as a JSON string
    in the user_agent field so they appear in the existing audit log
    without requiring a schema change.
    """
    entry = models.AuditLog(
        invoice_id=None,
        ip_address=request.client.host if request.client else "unknown",
        is_success=True,
        user_agent=json.dumps({
            "actor": "super_admin",
            "action": action,
            "target": target,
            **details,
        }, default=str),
    )
    db.add(entry)
    # Do NOT commit here — the caller commits after its own DB changes


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
    await _superadmin_audit(db, request, "create_tenant", slug,
                            {"name": name, "plan": plan})
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
    request: Request,
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
    changes: dict = {}
    if plan is not None:
        changes["plan"] = plan
        tenant.plan = plan
    if max_licenses is not None:
        changes["max_licenses"] = max_licenses
        tenant.max_licenses = max_licenses
    if max_vault_mb is not None:
        changes["max_vault_mb"] = max_vault_mb
        tenant.max_vault_mb = max_vault_mb
    if is_active is not None:
        changes["is_active"] = is_active
        tenant.is_active = is_active
    await _superadmin_audit(db, request, "update_tenant", slug, {"changes": changes})
    await db.commit()
    await redis_service.cache_delete(f"tenant:{slug}")
    return {"slug": slug, "updated": True}


@router.delete("/superadmin/tenants/{slug}", status_code=200)
async def delete_tenant(
    slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_super_admin),
):
    """
    Delete a tenant and CASCADE all owned data:
    LicenseContent → ViewAnalytics → OfflineTokens → AuditLog →
    LeakReports → VaultContents → Licenses → Tenant.

    This is irreversible. S3 vault objects are NOT deleted (they must be
    removed separately to avoid accidental data loss from orphaned keys).
    """
    result = await db.execute(
        select(models.Tenant).where(models.Tenant.slug == slug)
    )
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tid = tenant.id

    # Collect all licenses for this tenant (needed for foreign-key cascades)
    lic_result = await db.execute(
        select(models.License).where(models.License.tenant_id == tid)
    )
    license_ids = [lic.id for lic in lic_result.scalars().all()]

    # 1. LicenseContent grants (FK → licenses.id)
    if license_ids:
        lc_result = await db.execute(
            select(models.LicenseContent).where(
                models.LicenseContent.license_id.in_(license_ids)
            )
        )
        for row in lc_result.scalars().all():
            await db.delete(row)

    # 2. ViewAnalytics (tenant_id FK)
    va_result = await db.execute(
        select(models.ViewAnalytics).where(models.ViewAnalytics.tenant_id == tid)
    )
    for row in va_result.scalars().all():
        await db.delete(row)

    # 3. OfflineTokens (tenant_id FK)
    ot_result = await db.execute(
        select(models.OfflineToken).where(models.OfflineToken.tenant_id == tid)
    )
    for row in ot_result.scalars().all():
        await db.delete(row)

    # 4. AuditLog (tenant_id FK)
    al_result = await db.execute(
        select(models.AuditLog).where(models.AuditLog.tenant_id == tid)
    )
    for row in al_result.scalars().all():
        await db.delete(row)

    # 5. LeakReports (tenant_id FK)
    lr_result = await db.execute(
        select(models.LeakReport).where(models.LeakReport.tenant_id == tid)
    )
    for row in lr_result.scalars().all():
        await db.delete(row)

    # 6. VaultContents (tenant_id FK)
    vc_result = await db.execute(
        select(models.VaultContent).where(models.VaultContent.tenant_id == tid)
    )
    for row in vc_result.scalars().all():
        await db.delete(row)

    # 7. Licenses (tenant_id FK)
    lic2_result = await db.execute(
        select(models.License).where(models.License.tenant_id == tid)
    )
    for row in lic2_result.scalars().all():
        await db.delete(row)

    # 8. Tenant itself
    await db.delete(tenant)
    # Audit log goes to the *global* audit table (tenant_id=None) since
    # the tenant's own audit rows have already been deleted above.
    await _superadmin_audit(db, request, "delete_tenant", slug,
                            {"licenses_deleted": len(license_ids)})
    await db.commit()
    await redis_service.cache_delete(f"tenant:{slug}")

    return {"status": "deleted", "slug": slug}
