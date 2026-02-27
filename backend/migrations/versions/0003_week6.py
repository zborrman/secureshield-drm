"""Week 6 — owner email, offline token revocation reason.

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-27 00:00:00.000000

Changes:
  - licenses.owner_email          (String, nullable)  — contact email for key delivery
  - offline_tokens.revocation_reason (String, nullable) — reason stored on revocation
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "licenses",
        sa.Column("owner_email", sa.String(), nullable=True),
    )
    op.add_column(
        "offline_tokens",
        sa.Column("revocation_reason", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("offline_tokens", "revocation_reason")
    op.drop_column("licenses", "owner_email")
