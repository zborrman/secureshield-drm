"""
Central configuration — all env-vars and tunable constants live here.
Import from this module instead of calling os.getenv() scattered across the codebase.
"""
import os

# ── Authentication secrets ─────────────────────────────────────────────────────
ADMIN_API_KEY        = os.getenv("ADMIN_API_KEY", "")
OFFLINE_TOKEN_SECRET = os.getenv("OFFLINE_TOKEN_SECRET", ADMIN_API_KEY + "-offline-v1")
# Separate secret for vault access JWTs — prevents offline-token holders from forging vault tokens
VAULT_TOKEN_SECRET   = os.getenv("VAULT_TOKEN_SECRET", OFFLINE_TOKEN_SECRET + "-vault-v1")
SUPER_ADMIN_KEY      = os.getenv("SUPER_ADMIN_KEY", "")

# ── Session & bot-detection thresholds ────────────────────────────────────────
BOT_THRESHOLD_MS          = 500   # first heartbeat faster than this (ms) → bot suspect
SESSION_ACTIVE_MINUTES    = 5     # sessions silent for >5 min are considered expired
BRUTE_FORCE_WINDOW_MINUTES = 15   # sliding window for failed-attempt counting
BRUTE_FORCE_MAX_FAILS      = 5    # max failures within the window before IP is blocked

# ── Content Vault ──────────────────────────────────────────────────────────────
VAULT_ACCESS_TOKEN_MINUTES = 5    # short-lived vault access JWTs

# ── CORS ──────────────────────────────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
