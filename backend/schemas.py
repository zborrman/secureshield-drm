"""
Pydantic schemas for SecureShield DRM API request/response validation.

Using explicit schemas gives us:
  - Auto-generated, accurate OpenAPI docs
  - Response filtering (no accidental field leakage)
  - Input validation with clear error messages
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── License (requests) ────────────────────────────────────────────────────────

class CreateLicenseRequest(BaseModel):
    invoice_id: str = Field(..., max_length=128, description="Unique invoice identifier")
    owner_id: str = Field(..., max_length=128, description="Owner / user identifier")
    max_sessions: int = Field(default=1, ge=1, le=100, description="Max concurrent sessions")
    allowed_countries: str = Field(
        default="",
        max_length=512,
        description="Comma-separated ISO 3166-1 alpha-2 country codes, e.g. 'US,GB,DE'. Empty = unrestricted.",
    )
    is_paid: bool = Field(default=False, description="Mark license as pre-paid")
    expires_at: Optional[datetime] = Field(default=None, description="UTC expiry timestamp. None = never expires.")


class IssueOfflineTokenRequest(BaseModel):
    invoice_id: str = Field(..., max_length=128)
    hours: int = Field(default=24, ge=1, le=168, description="Token validity in hours (max 7 days)")
    device_hint: str = Field(default="", max_length=256, description="Human-readable device label")


# ── Tenant (requests) ─────────────────────────────────────────────────────────

class CreateTenantRequest(BaseModel):
    name: str = Field(..., max_length=128, description="Display name of the tenant organisation")
    slug: str = Field(..., max_length=64, pattern=r"^[a-z0-9-]+$", description="URL-safe identifier, lowercase alphanumeric and hyphens")
    admin_key: str = Field(..., min_length=16, max_length=256, description="Plain-text admin key (stored as bcrypt hash)")
    plan: str = Field(default="starter", max_length=32)
    max_licenses: int = Field(default=10, ge=1, le=100_000)
    max_vault_mb: int = Field(default=100, ge=1, le=51_200)


# ── License (responses) ────────────────────────────────────────────────────────

class LicenseCreatedResponse(BaseModel):
    invoice_id: str
    plain_key_to_copy: str
    warning: str


class LicenseOut(BaseModel):
    id: int
    invoice_id: str
    owner_id: str
    is_paid: bool
    max_sessions: int
    allowed_countries: Optional[str] = None
    expires_at: Optional[datetime] = None
    tenant_id: Optional[int] = None

    model_config = {"from_attributes": True}


# ── Offline Token ──────────────────────────────────────────────────────────────

class OfflineTokenIssued(BaseModel):
    token_id: str
    invoice_id: str
    valid_until: str
    max_offline_hours: int
    device_hint: Optional[str] = None
    token: str


class OfflineTokenEntry(BaseModel):
    token_id: str
    invoice_id: str
    issued_at: str
    valid_until: str
    max_offline_hours: int
    device_hint: Optional[str] = None
    is_revoked: bool
    is_expired: bool
    hours_remaining: int


# ── Vault ──────────────────────────────────────────────────────────────────────

class VaultAccessRequest(BaseModel):
    """Sent as JSON body to POST /vault/access/{content_id}.

    Keeping credentials in the request body (not query params) prevents them
    from appearing in server access logs, CDN logs, and browser history.
    """
    invoice_id: str = Field(..., max_length=128)
    license_key: str = Field(..., min_length=1, max_length=256)


class VaultUploadResponse(BaseModel):
    content_id: str
    filename: Optional[str] = None
    size_bytes: int
    content_type: str
    uploaded_at: str


class VaultItemOut(BaseModel):
    content_id: str
    filename: Optional[str] = None
    content_type: str
    size_bytes: int
    description: Optional[str] = None
    uploaded_at: str


# ── Tenant (SuperAdmin) ────────────────────────────────────────────────────────

class TenantOut(BaseModel):
    id: int
    name: str
    slug: str
    plan: str
    max_licenses: int
    max_vault_mb: int
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantCreatedResponse(BaseModel):
    id: int
    name: str
    slug: str
    plan: str
    max_licenses: int
    max_vault_mb: int


# ── Anomaly ────────────────────────────────────────────────────────────────────

class AnomalySummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class AnomalyResponse(BaseModel):
    findings: list[dict]
    summary: AnomalySummary


# ── Audit / Analytics ──────────────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: int
    invoice_id: Optional[str] = None
    ip_address: Optional[str] = None
    is_success: bool
    user_agent: Optional[str] = None
    timestamp: datetime
    tenant_id: Optional[int] = None

    model_config = {"from_attributes": True}


class SessionOut(BaseModel):
    id: int
    license_id: int
    content_id: Optional[str] = None
    start_time: datetime
    last_heartbeat: datetime
    duration_seconds: int
    is_bot_suspect: bool
    ip_address: Optional[str] = None
    device_info: Optional[str] = None
    tenant_id: Optional[int] = None

    model_config = {"from_attributes": True}
