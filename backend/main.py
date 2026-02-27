"""
SecureShield DRM — application entry point.

Responsibilities of this file:
  - Configure structured logging (JSON, with X-Request-ID correlation)
  - Create the FastAPI app instance
  - Register middleware (CORS, security headers, request logging, rate-limit handler)
  - Include all domain routers
  - Handle startup / shutdown lifecycle (secrets validation, DB tables, Redis)
"""
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from logging_config import setup_logging, get_logger
from database import engine, Base
import redis_service
from config import CORS_ORIGINS, validate_secrets
from rate_limit import limiter

# ── Logging ───────────────────────────────────────────────────────────────────
setup_logging()
logger = get_logger(__name__)

# ── Routers ───────────────────────────────────────────────────────────────────
from routers import auth, admin, vault, superadmin, tenant


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Single entry point for startup and shutdown logic.

    Replaces the deprecated @app.on_event("startup") / ("shutdown") pattern.
    FastAPI guarantees the code before `yield` runs before the first request,
    and the code after `yield` runs after the last request.
    """
    # ── startup ──
    validate_secrets()   # raises RuntimeError with details if any secret is missing/weak
    logger.info("startup", extra={"status": "ok", "db": "creating_tables"})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield  # application runs here

    # ── shutdown ──
    logger.info("shutdown", extra={"status": "closing_redis"})
    await redis_service.close_redis()


# ── Request-ID + access-log middleware ────────────────────────────────────────

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Assigns a unique X-Request-ID to every request (echoed in the response),
    and emits a structured access-log entry with method, path, status, and
    duration once the response is complete.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        start = time.perf_counter()

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response


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
        response.headers["X-API-Version"] = "1.0.0"
        return response


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecureShield DRM API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Attach the limiter so slowapi can find it via app.state
app.state.limiter = limiter

# Rate-limit exceeded -> 429 JSON response
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware is applied in reverse order (last added = outermost)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)

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

# ── Prometheus metrics ─────────────────────────────────────────────────────────
# Exposes GET /metrics in Prometheus text format.
# In production, restrict this endpoint to internal networks via a reverse-proxy
# rule (e.g. nginx allow 10.0.0.0/8; deny all;) so scrapers can reach it but
# the public internet cannot.

import platform as _platform
from prometheus_fastapi_instrumentator import Instrumentator  # noqa: E402
from prometheus_client import Info as _Prom_Info  # noqa: E402

Instrumentator(
    should_group_status_codes=False,
    should_instrument_requests_inprogress=False,
).instrument(app).expose(app, include_in_schema=False)

# Build-info gauge — exposes version and Python runtime for Grafana annotations
_build_info = _Prom_Info("drm_build", "SecureShield DRM build metadata")
_build_info.info({"version": "1.0.0", "python": _platform.python_version()})

# ── OpenTelemetry tracing (opt-in via OTEL_ENABLED=true) ──────────────────────
# When OTEL_ENABLED is unset or "false" the OTel packages are never imported —
# zero overhead on the hot path.  Set OTEL_ENDPOINT to point at a Jaeger or
# any OTLP-compatible collector (default: http://localhost:4317).
import os as _os

if _os.getenv("OTEL_ENABLED", "false").lower() == "true":
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    _otel_endpoint = _os.getenv("OTEL_ENDPOINT", "http://localhost:4317")
    _provider = TracerProvider()
    _provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=_otel_endpoint, insecure=True))
    )
    trace.set_tracer_provider(_provider)
    FastAPIInstrumentor.instrument_app(app)
    logger.info("otel_enabled", extra={"endpoint": _otel_endpoint})
