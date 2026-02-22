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


# ── License ────────────────────────────────────────────────────────────────────

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
