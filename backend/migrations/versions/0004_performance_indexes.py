"""Performance indexes — composite and covering indexes for hot query paths.

Revision ID: 0004
Revises: 0003
Create Date: 2026-02-27 00:00:00.000000

Changes:
  - idx_audit_invoice_ts         — (audit_logs.invoice_id, audit_logs.timestamp)
  - idx_audit_timestamp          — (audit_logs.timestamp)
  - idx_analytics_start_time     — (view_analytics.start_time)
  - idx_analytics_license_tenant — (view_analytics.license_id, view_analytics.tenant_id)
  - idx_licenses_is_paid         — (licenses.is_paid)

Rationale:
  The audit-log cursor pagination and anomaly detection run
  ORDER BY timestamp DESC and WHERE invoice_id = ? queries that were
  doing sequential scans on large tables.  These composite indexes
  convert them to index range scans.  The analytics index speeds up
  per-license session lookups across tenant-scoped queries.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "idx_audit_invoice_ts",
        "audit_logs",
        ["invoice_id", "timestamp"],
    )
    op.create_index(
        "idx_audit_timestamp",
        "audit_logs",
        ["timestamp"],
    )
    op.create_index(
        "idx_analytics_start_time",
        "view_analytics",
        ["start_time"],
    )
    op.create_index(
        "idx_analytics_license_tenant",
        "view_analytics",
        ["license_id", "tenant_id"],
    )
    op.create_index(
        "idx_licenses_is_paid",
        "licenses",
        ["is_paid"],
    )


def downgrade() -> None:
    op.drop_index("idx_licenses_is_paid", table_name="licenses")
    op.drop_index("idx_analytics_license_tenant", table_name="view_analytics")
    op.drop_index("idx_analytics_start_time", table_name="view_analytics")
    op.drop_index("idx_audit_timestamp", table_name="audit_logs")
    op.drop_index("idx_audit_invoice_ts", table_name="audit_logs")
