# Changelog

All notable changes to SecureShield DRM System are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2026-02-27

### Added

**Core DRM**
- License verification with brute-force protection (sliding 15-min window, 5-fail lockout per IP)
- Stripe Checkout + Webhook integration with dead-letter queue for failed events
- Forensic watermarking: SHA-256 owner fingerprint embedded per viewing session
- Geofencing: per-license country allowlist enforced at verify time via ip-api.com
- Session orchestration: Redis-backed session registry + real-time SSE revocation stream
- Proof-of-Leak: tamper-evident legal reports with SHA-256 integrity hash
- Offline tokens: HS256 JWTs with server-side `jti` revocation list, configurable TTL

**Content Vault**
- AES-256-GCM per-file encryption; per-file key wrapped with Fernet (VAULT_MASTER_KEY)
- Encrypted S3 storage; presigned streaming via short-lived vault access JWTs
- Per-content license grants (deny-by-default once any grant is added)
- Tenant vault partitioning (`vault/{tenant_slug}/{id}.enc`)

**Multi-Tenant SaaS**
- Shared-schema multi-tenancy with `tenant_id` FK on all domain tables
- Tenant authentication: `X-Tenant-ID` (slug) + `X-Admin-Key` (bcrypt-verified)
- Super-admin provisioning API (`/superadmin/tenants` CRUD with cascade delete)
- Per-tenant plan limits (`max_licenses`, `max_vault_mb`)
- Tenant Redis cache (TTL=300s) with invalidation on PATCH/DELETE

**AI Anomaly Discovery**
- 7-detector statistical heuristic engine:
  - `ip_velocity` — many distinct IPs per license in short window
  - `session_flood` — burst of sessions from one license
  - `bot_pattern` — high ratio of `is_bot_suspect` sessions
  - `brute_force_cluster` — failed auth attempts by IP
  - `credential_sharing` — many distinct user-agents per license
  - `duration_anomaly` — suspiciously short mean session duration
  - `multi_country` — geographically impossible access spread
- Severity scoring (LOW/MEDIUM/HIGH/CRITICAL) with natural-language recommendations
- `/admin/anomalies` + `/admin/anomalies/summary` + `/tenant/anomalies`

**Authentication & Authorization**
- Admin session JWTs: `POST /admin/login` → HS256 JWT (15-min TTL by default)
- TOTP 2FA: optional RFC 4226 enforcement on admin login
- JWT signed with `ADMIN_SESSION_SECRET` (SHA-256 derived if unset; always ≥32 bytes)
- Startup validator: server refuses to start with weak/missing secrets

**Observability**
- Prometheus metrics at `/metrics` via `prometheus-fastapi-instrumentator`
- `drm_build_info` gauge with `version` and `python` labels
- `drm_redis_cache_hits_total` / `drm_redis_cache_misses_total` counters
- `drm_license_verifications_total` labelled by status
- SLO recording rules: `job:http_request_rate5m:sum`, `job:http_error_rate5m:ratio`,
  `job:http_p99_latency5m:seconds`
- Docker Compose full-stack: Redis, Prometheus, Grafana, AlertManager, Jaeger
- 4 Prometheus alert rules: HighErrorRate, RateLimitedRequestsSpike,
  RedisCacheUnavailable, BackendDown
- Grafana auto-provisioned 6-panel dashboard
- Opt-in OpenTelemetry tracing via `OTEL_ENABLED=true` → Jaeger

**Developer Experience**
- Alembic async migrations (`0001` initial schema → `0004` performance indexes)
- 5 composite DB indexes for hot query paths (audit-log pagination, analytics lookup)
- Cursor pagination on all list endpoints (`skip`, `limit`, max 500)
- `GET /admin/vault/{id}/presign` presigned URL shortcut
- Bulk license import: `POST /admin/licenses/bulk` (CSV upload)
- GDPR endpoints: Subject Access Request export + right-to-be-forgotten purge
- `X-API-Version: 1.0.0` header on every response
- `X-Request-ID` correlation header on every response
- Full OpenAPI 3.1 contract (`openapi.yaml`)

**CI/CD**
- GitHub Actions: full CI (`main_ci.yml`) — Rust build, pytest + PostgreSQL, Playwright E2E
- PR fast-check workflow (`pr-review.yml`) — ruff, ESLint, tsc, pytest SQLite
- Automated issue management on CI failure (`on-failure.yml`)
- Dependabot weekly grouped updates (github-actions, pip, npm)

### Fixed

- `datetime.utcnow()` deprecation (Python 3.12+): replaced with
  `datetime.now(timezone.utc).replace(tzinfo=None)` throughout `anomaly_service.py`
  to remain compatible with naive DB-stored datetimes
- `bcrypt==3.2.2` pinned to maintain `passlib` compatibility (bcrypt 4+ breaks
  `passlib 1.7.4` due to missing `__about__.__version__`)
- PyJWT HS256 key length: `_admin_session_secret()` now always returns ≥32 bytes
  via SHA-256 derivation when `ADMIN_SESSION_SECRET` is not explicitly set

### Security

- TOTP 2FA enforcement on admin login
- Startup validator blocks launch with weak/missing secrets
- `frame-ancestors 'none'` in Content-Security-Policy (clickjacking prevention)
- HSTS with 2-year `max-age` and `includeSubDomains; preload`
- Rate limiting per role: public, admin, super-admin, tenant write
- Redis circuit breaker: graceful degradation when Redis is unreachable
- Timing-safe secret comparison (`hmac.compare_digest`) in all auth checks

---

## [0.9.0] - 2026-02-01

Initial private preview release. Core license verification, Stripe payments,
audit log, analytics session tracking.
