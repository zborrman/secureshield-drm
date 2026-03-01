"""
Category B — Database performance indexes (migration 0004).

Tests:
  1. All 5 index names from migration 0004 exist in the DB after table creation
  2. All index names follow the idx_ convention
  3. Audit-log ORDER BY timestamp DESC query executes without error
  4. Analytics compound query (license_id + tenant_id) executes without error
"""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, inspect as sa_inspect


_EXPECTED_INDEXES = [
    "idx_audit_invoice_ts",
    "idx_audit_timestamp",
    "idx_analytics_start_time",
    "idx_analytics_license_tenant",
    "idx_licenses_is_paid",
]

_INDEXED_TABLES = ["audit_logs", "view_analytics", "licenses"]


@pytest.mark.asyncio
async def test_migration_0004_indexes_exist(db_session: AsyncSession):
    """All 5 indexes from migration 0004 must exist in the test DB after create_all."""

    def _collect_indexes(conn):
        inspector = sa_inspect(conn)
        names = set()
        for table in _INDEXED_TABLES:
            for idx in inspector.get_indexes(table):
                if idx.get("name"):
                    names.add(idx["name"])
        return names

    async with db_session.bind.connect() as conn:
        existing = await conn.run_sync(_collect_indexes)

    for idx_name in _EXPECTED_INDEXES:
        assert idx_name in existing, (
            f"Index '{idx_name}' not found. "
            f"Existing indexes: {sorted(existing)}"
        )


def test_index_names_follow_convention():
    """All migration 0004 index names must start with 'idx_'."""
    for name in _EXPECTED_INDEXES:
        assert name.startswith("idx_"), f"Index name '{name}' must start with 'idx_'"


@pytest.mark.asyncio
async def test_audit_log_ordered_query_succeeds(db_session: AsyncSession):
    """ORDER BY timestamp DESC on audit_logs must execute without error."""
    result = await db_session.execute(
        text("SELECT id, invoice_id FROM audit_logs ORDER BY timestamp DESC LIMIT 10")
    )
    rows = result.fetchall()
    assert isinstance(rows, list)


@pytest.mark.asyncio
async def test_analytics_compound_query_succeeds(db_session: AsyncSession):
    """Compound WHERE license_id=? AND tenant_id IS NULL on view_analytics must succeed."""
    result = await db_session.execute(
        text(
            "SELECT id FROM view_analytics "
            "WHERE license_id = 1 AND tenant_id IS NULL "
            "ORDER BY start_time DESC LIMIT 10"
        )
    )
    rows = result.fetchall()
    assert isinstance(rows, list)
