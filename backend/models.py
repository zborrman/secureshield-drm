from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from datetime import datetime
from database import Base

class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(String, unique=True, index=True)
    license_key = Column(String, unique=True)
    is_paid = Column(Boolean, default=False)
    owner_id = Column(String)
    max_sessions = Column(Integer, default=1)       # concurrent viewing slots allowed
    allowed_countries = Column(String, nullable=True)  # NULL = unrestricted; "US,GB" = restrict

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    invoice_id = Column(String, index=True)
    ip_address = Column(String)
    is_success = Column(Boolean)
    user_agent = Column(String)

class ViewAnalytics(Base):
    __tablename__ = "view_analytics"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), index=True)
    content_id = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    duration_seconds = Column(Integer, default=0)
    device_info = Column(String)
    ip_address = Column(String)
    is_bot_suspect = Column(Boolean, default=False)  # True if first heartbeat < 500ms after start


class LeakReport(Base):
    __tablename__ = "leak_reports"

    id = Column(String, primary_key=True)          # UUID4 string
    generated_at = Column(DateTime, default=datetime.utcnow)
    invoice_id = Column(String, nullable=True, index=True)
    submitted_fingerprint = Column(String, nullable=True)
    evidence_json = Column(Text)                   # canonical JSON blob (used for integrity check)
    integrity_hash = Column(String)                # sha256:<hex> of evidence_json


class OfflineToken(Base):
    __tablename__ = "offline_tokens"

    id = Column(String, primary_key=True)          # UUID4 — also the JWT jti claim
    invoice_id = Column(String, index=True)
    issued_at = Column(DateTime, default=datetime.utcnow)
    valid_until = Column(DateTime)                 # UTC expiry stored server-side for listing
    max_offline_hours = Column(Integer)
    is_revoked = Column(Boolean, default=False)
    device_hint = Column(String, nullable=True)    # free-text label set by admin (e.g. "Alice laptop")


class VaultContent(Base):
    __tablename__ = "vault_contents"

    id = Column(String, primary_key=True)          # UUID4
    filename = Column(String)                      # original filename (e.g. "report.pdf")
    content_type = Column(String)                  # MIME type
    size_bytes = Column(Integer)                   # plaintext size (before encryption)
    s3_key = Column(String)                        # S3 object path: "vault/{id}.enc"
    encrypted_key = Column(Text)                   # Fernet-wrapped AES-256 key
    iv = Column(String)                            # AES-GCM nonce (base64)
    description = Column(String, nullable=True)    # admin-supplied label
    uploaded_at = Column(DateTime, default=datetime.utcnow)
