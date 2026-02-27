"""Week 5 — license expiry + proof-of-leak dedup.

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-27 00:00:00.000000

Changes:
  - licenses.expires_at  (DateTime, nullable)       — None = never expires
  - leak_reports.invoice_id UNIQUE index             — prevent duplicate reports per invoice
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add expires_at column to licenses table
    op.add_column(
        "licenses",
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )

    # Add UNIQUE index on leak_reports.invoice_id
    # NULL values are exempt from uniqueness in both SQLite and PostgreSQL,
    # so fingerprint-only reports (invoice_id=NULL) are unaffected.
    op.create_index(
        "uq_leak_invoice",
        "leak_reports",
        ["invoice_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_leak_invoice", table_name="leak_reports")
    op.drop_column("licenses", "expires_at")
