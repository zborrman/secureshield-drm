"""Initial schema — all 8 tables.

Revision ID: 0001
Revises:
Create Date: 2026-02-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── tenants ───────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("admin_key_hash", sa.String(), nullable=False),
        sa.Column("plan", sa.String(), nullable=True),
        sa.Column("max_licenses", sa.Integer(), nullable=True),
        sa.Column("max_vault_mb", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tenants_id", "tenants", ["id"], unique=False)
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)

    # ── licenses ──────────────────────────────────────────────────────────────
    op.create_table(
        "licenses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("invoice_id", sa.String(), nullable=True),
        sa.Column("license_key", sa.String(), nullable=True),
        sa.Column("is_paid", sa.Boolean(), nullable=True),
        sa.Column("owner_id", sa.String(), nullable=True),
        sa.Column("max_sessions", sa.Integer(), nullable=True),
        sa.Column("allowed_countries", sa.String(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invoice_id"),
        sa.UniqueConstraint("license_key"),
    )
    op.create_index("ix_licenses_id", "licenses", ["id"], unique=False)
    op.create_index("ix_licenses_invoice_id", "licenses", ["invoice_id"], unique=False)
    op.create_index("ix_licenses_tenant_id", "licenses", ["tenant_id"], unique=False)

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("invoice_id", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("is_success", sa.Boolean(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"], unique=False)
    op.create_index("ix_audit_logs_invoice_id", "audit_logs", ["invoice_id"], unique=False)
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"], unique=False)

    # ── view_analytics ────────────────────────────────────────────────────────
    op.create_table(
        "view_analytics",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("license_id", sa.Integer(), nullable=True),
        sa.Column("content_id", sa.String(), nullable=True),
        sa.Column("start_time", sa.DateTime(), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("device_info", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("is_bot_suspect", sa.Boolean(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["license_id"], ["licenses.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_view_analytics_id", "view_analytics", ["id"], unique=False)
    op.create_index("ix_view_analytics_license_id", "view_analytics", ["license_id"], unique=False)
    op.create_index("ix_view_analytics_tenant_id", "view_analytics", ["tenant_id"], unique=False)

    # ── leak_reports ──────────────────────────────────────────────────────────
    op.create_table(
        "leak_reports",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=True),
        sa.Column("invoice_id", sa.String(), nullable=True),
        sa.Column("submitted_fingerprint", sa.String(), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=True),
        sa.Column("integrity_hash", sa.String(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_leak_reports_invoice_id", "leak_reports", ["invoice_id"], unique=False)
    op.create_index("ix_leak_reports_tenant_id", "leak_reports", ["tenant_id"], unique=False)

    # ── offline_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "offline_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("invoice_id", sa.String(), nullable=True),
        sa.Column("issued_at", sa.DateTime(), nullable=True),
        sa.Column("valid_until", sa.DateTime(), nullable=True),
        sa.Column("max_offline_hours", sa.Integer(), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=True),
        sa.Column("device_hint", sa.String(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_offline_tokens_invoice_id", "offline_tokens", ["invoice_id"], unique=False)
    op.create_index("ix_offline_tokens_tenant_id", "offline_tokens", ["tenant_id"], unique=False)

    # ── vault_contents ────────────────────────────────────────────────────────
    op.create_table(
        "vault_contents",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=True),
        sa.Column("content_type", sa.String(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("s3_key", sa.String(), nullable=True),
        sa.Column("encrypted_key", sa.Text(), nullable=True),
        sa.Column("iv", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vault_contents_tenant_id", "vault_contents", ["tenant_id"], unique=False)

    # ── license_contents ──────────────────────────────────────────────────────
    op.create_table(
        "license_contents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("license_id", sa.Integer(), nullable=False),
        sa.Column("content_id", sa.String(), nullable=False),
        sa.Column("granted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["content_id"], ["vault_contents.id"]),
        sa.ForeignKeyConstraint(["license_id"], ["licenses.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("license_id", "content_id", name="uq_license_content"),
    )
    op.create_index("ix_license_contents_id", "license_contents", ["id"], unique=False)
    op.create_index("ix_license_contents_license_id", "license_contents", ["license_id"], unique=False)
    op.create_index("ix_license_contents_content_id", "license_contents", ["content_id"], unique=False)


def downgrade() -> None:
    op.drop_table("license_contents")
    op.drop_table("vault_contents")
    op.drop_table("offline_tokens")
    op.drop_table("leak_reports")
    op.drop_table("view_analytics")
    op.drop_table("audit_logs")
    op.drop_table("licenses")
    op.drop_table("tenants")
