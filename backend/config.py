"""
Central configuration — all env-vars and tunable constants live here.
Import from this module instead of calling os.getenv() scattered across the codebase.

REQUIRED secrets (the app refuses to start without them — see validate_secrets()):
  ADMIN_API_KEY          — master admin key (≥ 32 chars recommended)
  OFFLINE_TOKEN_SECRET   — HS256 signing secret for offline JWTs (≥ 32 bytes REQUIRED)
  VAULT_TOKEN_SECRET     — HS256 signing secret for vault-access JWTs (≥ 32 bytes REQUIRED)
  SUPER_ADMIN_KEY        — super-admin key for /superadmin/* endpoints
"""
import os

# ── Authentication secrets ─────────────────────────────────────────────────────
# Each secret is read independently from the environment.
# There are NO derived fallbacks — a predictable fallback is a security vulnerability.
# In development/test, set these in your .env file or conftest.py.
ADMIN_API_KEY        = os.getenv("ADMIN_API_KEY", "")
OFFLINE_TOKEN_SECRET = os.getenv("OFFLINE_TOKEN_SECRET", "")
VAULT_TOKEN_SECRET   = os.getenv("VAULT_TOKEN_SECRET", "")
SUPER_ADMIN_KEY      = os.getenv("SUPER_ADMIN_KEY", "")

# ── Admin TOTP / 2FA ──────────────────────────────────────────────────────────
# Base-32 TOTP secret (RFC 4226).  Leave empty to disable TOTP enforcement.
# Generate with: python -c "import pyotp; print(pyotp.random_base32())"
ADMIN_TOTP_SECRET = os.getenv("ADMIN_TOTP_SECRET", "")
# TTL (seconds) for the short-lived admin session JWTs issued by /admin/login.
ADMIN_SESSION_TTL = int(os.getenv("ADMIN_SESSION_TTL", "900"))   # default 15 min


def validate_secrets() -> None:
    """Fail fast at startup if any required secret is missing or too short.

    Call this from the FastAPI lifespan handler so the process exits immediately
    with a clear error message rather than producing subtle security failures later.
    HS256 requires a minimum key size of 256 bits (32 bytes).
    """
    errors: list[str] = []
    _required = {
        "ADMIN_API_KEY":        (ADMIN_API_KEY,        16),
        "OFFLINE_TOKEN_SECRET": (OFFLINE_TOKEN_SECRET, 32),
        "VAULT_TOKEN_SECRET":   (VAULT_TOKEN_SECRET,   32),
        "SUPER_ADMIN_KEY":      (SUPER_ADMIN_KEY,      16),
    }
    for name, (value, min_len) in _required.items():
        if not value:
            errors.append(f"  {name} is not set")
        elif len(value) < min_len:
            errors.append(f"  {name} is too short ({len(value)} chars, minimum {min_len})")
    if errors:
        raise RuntimeError(
            "SecureShield startup aborted — insecure configuration:\n"
            + "\n".join(errors)
            + "\n\nSet the missing environment variables and restart."
        )

# ── Session & bot-detection thresholds ────────────────────────────────────────
BOT_THRESHOLD_MS           = 500   # first heartbeat faster than this (ms) → bot suspect
SESSION_ACTIVE_MINUTES     = 5     # sessions silent for >5 min are considered expired
BRUTE_FORCE_WINDOW_MINUTES = 15    # sliding window for failed-attempt counting
BRUTE_FORCE_MAX_FAILS      = 5     # max failures within the window before IP is blocked

# ── Content Vault ──────────────────────────────────────────────────────────────
VAULT_ACCESS_TOKEN_MINUTES = 5     # short-lived vault access JWTs (minutes)

# Hard size cap enforced before encryption — prevents DoS via huge uploads.
MAX_UPLOAD_MB    = int(os.getenv("MAX_UPLOAD_MB", "500"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Allowed MIME types for *tenant* vault uploads.
# Admin uploads are unrestricted (admins are trusted operators).
ALLOWED_VAULT_MIME: frozenset = frozenset({
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "video/mp4",
    "video/webm",
    "audio/mpeg",
    "audio/mp4",
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
})

# ── Geo-block webhook ─────────────────────────────────────────────────────────
# Optional URL to call when a request is geo-blocked.  Empty string = disabled.
GEO_WEBHOOK_URL = os.getenv("GEO_WEBHOOK_URL", "")

# ── CORS ──────────────────────────────────────────────────────────────────────
# Strip whitespace from each origin so "http://a.com, http://b.com" parses correctly.
CORS_ORIGINS: list[str] = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
