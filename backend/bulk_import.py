"""
Bulk license import helper.

Parses a CSV file and creates License rows in bulk.

Expected CSV columns (header row required):
  invoice_id        — required; must be unique
  owner_id          — required
  max_sessions      — optional int (default 1)
  allowed_countries — optional comma-sep country codes (default "" = unrestricted)
  is_paid           — optional bool: true/yes/1 → True (default false)
  expires_at        — optional ISO-8601 datetime (default None = never)
  owner_email       — optional email address (default None)

Rows with a duplicate invoice_id are recorded as "conflict" (not an error).
Rows with missing required fields or parse failures are recorded as "error".
All valid rows are committed in a single DB transaction; one bad row does not
roll back the whole batch.
"""

import csv
import io
import secrets as _secrets
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

import models
from auth_utils import hash_license_key
import email_service


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "yes", "1")


def _parse_optional_datetime(value: str) -> datetime | None:
    v = value.strip()
    if not v:
        return None
    return datetime.fromisoformat(v)


async def process_bulk_csv(
    csv_bytes: bytes,
    db: AsyncSession,
) -> dict[str, Any]:
    """Parse *csv_bytes* and create licenses.  Returns a result summary dict."""
    rows_out: list[dict] = []
    created = conflict = failed = 0

    text = csv_bytes.decode("utf-8-sig")  # strip BOM if present
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        return {"total": 0, "created": 0, "conflict": 0, "failed": 0, "rows": []}

    # Normalise header names (strip whitespace)
    reader.fieldnames = [f.strip() for f in reader.fieldnames]

    for line_num, row in enumerate(reader, start=2):
        row = {k.strip(): (v or "").strip() for k, v in row.items()}
        invoice_id = row.get("invoice_id", "")
        owner_id   = row.get("owner_id", "")

        if not invoice_id or not owner_id:
            rows_out.append({
                "invoice_id": invoice_id or f"<row {line_num}>",
                "status": "error",
                "plain_key": None,
                "error": "invoice_id and owner_id are required",
            })
            failed += 1
            continue

        # Parse optional fields
        try:
            max_sessions      = int(row.get("max_sessions", "") or "1")
            allowed_countries = (row.get("allowed_countries", "") or "").upper().strip() or None
            is_paid           = _parse_bool(row.get("is_paid", "false"))
            expires_at        = _parse_optional_datetime(row.get("expires_at", ""))
            owner_email       = row.get("owner_email", "").strip() or None
        except (ValueError, TypeError) as exc:
            rows_out.append({
                "invoice_id": invoice_id,
                "status": "error",
                "plain_key": None,
                "error": f"parse error: {exc}",
            })
            failed += 1
            continue

        # Duplicate check
        existing = await db.execute(
            select(models.License).where(models.License.invoice_id == invoice_id)
        )
        if existing.scalars().first():
            rows_out.append({
                "invoice_id": invoice_id,
                "status": "conflict",
                "plain_key": None,
                "error": "invoice_id already exists",
            })
            conflict += 1
            continue

        # Create the license
        plain_key  = f"SK-{_secrets.token_urlsafe(16)}"
        hashed_key = hash_license_key(plain_key)
        lic = models.License(
            invoice_id=invoice_id,
            license_key=hashed_key,
            owner_id=owner_id,
            is_paid=is_paid,
            max_sessions=max(1, min(max_sessions, 100)),
            allowed_countries=allowed_countries,
            expires_at=expires_at,
            owner_email=owner_email,
        )
        db.add(lic)
        try:
            await db.commit()
        except Exception as exc:
            await db.rollback()
            rows_out.append({
                "invoice_id": invoice_id,
                "status": "error",
                "plain_key": None,
                "error": f"db error: {exc}",
            })
            failed += 1
            continue

        # Optional email delivery (fire-and-forget; errors do not fail the row)
        if owner_email:
            await email_service.send_license_key(owner_email, invoice_id, plain_key)

        rows_out.append({
            "invoice_id": invoice_id,
            "status": "created",
            "plain_key": plain_key,
            "error": None,
        })
        created += 1

    return {
        "total":    created + conflict + failed,
        "created":  created,
        "conflict": conflict,
        "failed":   failed,
        "rows":     rows_out,
    }
