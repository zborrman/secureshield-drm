"""
Email service for SecureShield DRM.

Sends license keys to owners after creation.  Disabled by default — set
EMAIL_ENABLED=true in the environment to activate real SMTP delivery.

Environment variables:
  EMAIL_ENABLED   — "true" to enable SMTP send; any other value = stub (default: false)
  SMTP_HOST       — SMTP server hostname (default: localhost)
  SMTP_PORT       — SMTP server port (default: 587)
  SMTP_USER       — SMTP username / login (default: "")
  SMTP_PASS       — SMTP password (default: "")
  SMTP_FROM       — From address (default: noreply@secureshield.local)

When EMAIL_ENABLED != "true" the send function logs the would-be email and
returns True immediately — making it safe to call in all environments and easy
to test without a real SMTP server.
"""

import asyncio
import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)

EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST     = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "noreply@secureshield.local")


def _send_sync(to: str, invoice_id: str, plain_key: str) -> None:
    """Blocking SMTP send — called via asyncio.to_thread."""
    msg = EmailMessage()
    msg["Subject"] = f"Your SecureShield License Key — {invoice_id}"
    msg["From"]    = SMTP_FROM
    msg["To"]      = to
    msg.set_content(
        f"Your license has been activated.\n\n"
        f"Invoice ID : {invoice_id}\n"
        f"License Key: {plain_key}\n\n"
        f"Keep this key private — it grants access to protected content.\n"
        f"SecureShield DRM"
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        if SMTP_USER and SMTP_PASS:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


async def send_license_key(to: str, invoice_id: str, plain_key: str) -> bool:
    """Send the plain license key to *to*.

    Returns True on success (or when stub mode is active).
    Returns False and logs the error if SMTP delivery fails — never raises.
    """
    if not to:
        return True

    if not EMAIL_ENABLED:
        logger.info(
            "email_stub",
            extra={"to": to, "invoice_id": invoice_id, "note": "EMAIL_ENABLED=false"},
        )
        return True

    try:
        await asyncio.to_thread(_send_sync, to, invoice_id, plain_key)
        logger.info("email_sent", extra={"to": to, "invoice_id": invoice_id})
        return True
    except Exception as exc:
        logger.warning(
            "email_failed",
            extra={"to": to, "invoice_id": invoice_id, "error": str(exc)},
        )
        return False
