"""
SecureShield DRM — application entry point.

Responsibilities of this file:
  - Create the FastAPI app instance
  - Register middleware (CORS, security headers, rate-limit error handler)
  - Include all domain routers
  - Handle startup / shutdown lifecycle (secrets validation, DB tables, Redis)
"""
import logging

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, Base
import redis_service
from config import (
    CORS_ORIGINS,
    ADMIN_API_KEY,
    OFFLINE_TOKEN_SECRET,
    VAULT_TOKEN_SECRET,
    SUPER_ADMIN_KEY,
)
from rate_limit import limiter

# ── Routers ──────────────────────────────────────────────────────────────────
from routers import auth, admin, vault, superadmin, tenant

logger = logging.getLogger(__name__)

# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard security headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecureShield DRM API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach the limiter so slowapi can find it via app.state
app.state.limiter = limiter

# Rate-limit exceeded -> 429 JSON response
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include routers ───────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(vault.router)
app.include_router(superadmin.router)
app.include_router(tenant.router)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    """Validate critical secrets and create DB tables."""
    _problems: list[str] = []

    if not ADMIN_API_KEY:
        _problems.append("ADMIN_API_KEY is not set")
    if len(OFFLINE_TOKEN_SECRET) < 32:
        _problems.append(
            f"OFFLINE_TOKEN_SECRET is too short ({len(OFFLINE_TOKEN_SECRET)} chars, need >=32)"
        )
    if len(VAULT_TOKEN_SECRET) < 32:
        _problems.append(
            f"VAULT_TOKEN_SECRET is too short ({len(VAULT_TOKEN_SECRET)} chars, need >=32)"
        )
    if not SUPER_ADMIN_KEY:
        _problems.append("SUPER_ADMIN_KEY is not set")

    if _problems:
        msg = "Startup aborted — missing or weak secrets:\n  " + "\n  ".join(_problems)
        logger.critical(msg)
        raise RuntimeError(msg)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.on_event("shutdown")
async def shutdown() -> None:
    await redis_service.close_redis()
