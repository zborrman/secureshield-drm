"""
routers/provisioning.py
────────────────────────
Zero-friction onboarding API for Shadow Warden AI SMB installer.

Endpoints
─────────
  POST /api/provision   — issue trial key (email) or validate paid license key

Trial flow
──────────
  1. install.sh sends  {"email": "...", "is_trial": true}
  2. We check: has this email already used a trial? → 403
  3. We generate SWT-{26 chars} key, store as License with expires_at = now+14d
  4. Return {"status": "trial", "api_key": "SWT-...", "expires_at": "..."}

Paid flow
─────────
  1. install.sh sends  {"license_key": "SW-XXX-YYY-ZZZ", "is_trial": false}
  2. We look up the License, check is_paid=True and not expired
  3. Return {"status": "paid", "api_key": "...", "plan": "..."}

Abuse protection
────────────────
  - 5 requests/minute per IP (shared limiter)
  - One trial per email (DB check on owner_email)
  - Trial keys prefixed SWT- (easily distinguishable in logs from paid keys)
  - No anonymous trials: email required, stored for CRM / follow-up
"""
from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

import models
from dependencies import get_db
from rate_limit import limiter, _limit

router = APIRouter(prefix="/api", tags=["provisioning"])

# 5 provision requests per minute per IP — prevents trial farming
PROVISION_LIMIT = _limit("5/minute")

TRIAL_DAYS = 14


# ── Request / Response schemas ────────────────────────────────────────────────

class ProvisionRequest(BaseModel):
    email:       EmailStr | None = None
    license_key: str | None      = None
    is_trial:    bool            = False


class ProvisionResponse(BaseModel):
    status:     str             # "trial" | "paid"
    api_key:    str
    plan:       str             # "trial" | "smb" | "enterprise" | ...
    expires_at: str | None      # ISO-8601 or null (never expires)
    message:    str


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/provision", response_model=ProvisionResponse)
@limiter.limit(PROVISION_LIMIT)
async def provision(
    request: Request,
    payload: ProvisionRequest,
    db:      AsyncSession = Depends(get_db),
) -> ProvisionResponse:
    """
    Called by install.sh at customer's server.  Issues or validates a key.

    Trial:  POST /api/provision  {"email": "cto@acme.com", "is_trial": true}
    Paid:   POST /api/provision  {"license_key": "SW-XXX-YYY", "is_trial": false}
    """

    # ── TRIAL ─────────────────────────────────────────────────────────────────
    if payload.is_trial:
        if not payload.email:
            raise HTTPException(
                status_code=400,
                detail="email is required for trial activation.",
            )

        email_lower = payload.email.lower().strip()

        # One trial per email — check existing trial licenses
        existing = await db.execute(
            select(models.License).where(
                models.License.owner_email == email_lower,
                models.License.invoice_id.like("trial-%"),
            )
        )
        if existing.scalars().first():
            raise HTTPException(
                status_code=403,
                detail=(
                    "A trial has already been issued for this email. "
                    "Purchase a license at https://shadowwarden.ai/pricing"
                ),
            )

        # Generate trial key and store as License
        trial_key  = f"SWT-{secrets.token_urlsafe(19)}"
        invoice_id = f"trial-{uuid.uuid4().hex[:12]}"
        expires_at = datetime.now(UTC) + timedelta(days=TRIAL_DAYS)

        license_row = models.License(
            invoice_id       = invoice_id,
            license_key      = trial_key,
            is_paid          = False,
            owner_id         = f"trial:{email_lower}",
            owner_email      = email_lower,
            max_sessions     = 3,
            expires_at       = expires_at,
        )
        db.add(license_row)
        await db.commit()

        return ProvisionResponse(
            status     = "trial",
            api_key    = trial_key,
            plan       = "trial",
            expires_at = expires_at.isoformat(),
            message    = (
                f"14-day trial activated for {email_lower}. "
                "After expiry, purchase at https://shadowwarden.ai/pricing"
            ),
        )

    # ── PAID LICENSE ──────────────────────────────────────────────────────────
    if payload.license_key:
        key = payload.license_key.strip()

        result = await db.execute(
            select(models.License).where(models.License.license_key == key)
        )
        lic = result.scalars().first()

        if not lic:
            raise HTTPException(
                status_code=401,
                detail="License key not found. Check your key or contact support.",
            )

        if not lic.is_paid:
            raise HTTPException(
                status_code=402,
                detail="License is not yet activated. Complete payment at https://shadowwarden.ai/pricing",
            )

        # Expiry check
        if lic.expires_at and datetime.now(UTC) > lic.expires_at.replace(tzinfo=UTC):
            raise HTTPException(
                status_code=410,
                detail="License has expired. Renew at https://shadowwarden.ai/billing",
            )

        # Determine plan from invoice_id prefix (SW-SMB-... / SW-ENT-...)
        plan = "smb"
        inv  = (lic.invoice_id or "").upper()
        if "ENT" in inv or "ENTERPRISE" in inv:
            plan = "enterprise"
        elif "PRO" in inv:
            plan = "pro"

        return ProvisionResponse(
            status     = "paid",
            api_key    = lic.license_key,
            plan       = plan,
            expires_at = lic.expires_at.isoformat() if lic.expires_at else None,
            message    = f"License activated. Plan: {plan.upper()}. Welcome to Shadow Warden AI.",
        )

    raise HTTPException(
        status_code=400,
        detail="Provide either {'email': '...', 'is_trial': true} or {'license_key': '...'}",
    )
