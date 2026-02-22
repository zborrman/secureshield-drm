# SecureShield DRM — Backlog & TODO

> Last updated: 2026-02-22
> Status key: `[ ]` open · `[~]` in progress · `[x]` done

---

## Implemented Features

- [x] License generation (hashed key, invoice-based)
- [x] License verification with brute-force protection (5-fail IP block)
- [x] Security audit log (every verify attempt)
- [x] Stripe checkout + webhook → `is_paid` flip
- [x] Real-time view analytics (`start` → `heartbeat` → duration tracking)
- [x] Bot detection (first heartbeat < 500 ms → `is_bot_suspect`)
- [x] TrustScore component (% clean sessions)
- [x] Concurrent session limit (`max_sessions`, 409 on excess, admin revoke)
- [x] Dynamic geofencing (`allowed_countries`, live PATCH, ip-api.com lookup)
- [x] Proof-of-Leak legal evidence generator (tamper-evident SHA-256 sealed report)
- [x] Watermark fingerprint reverse-lookup (deterministic SHA-256[:4] → int32)
- [x] Zero-Knowledge Offline Viewing (HS256 JWT, client-side expiry check, revocation)
- [x] Admin dashboard (licenses table, audit trail, TrustScore, analytics chart, LeakReporter, OfflineTokenManager)
- [x] Content Vault — AES-256-GCM per-file encryption, Fernet key-wrapping, S3 storage, short-lived stream JWTs (`vault_service.py`, `/admin/vault/*`, `/vault/stream/*`, `ContentVault.tsx`)
- [x] Multi-Tenant SaaS — Tenant model, super-admin CRUD, per-tenant vault quota, full data isolation (`/superadmin/*`, `/tenant/*`, `SuperAdminDashboard.tsx`, `TenantDashboard.tsx`)
- [x] AI Anomaly Pattern Discovery — 7 statistical detectors, severity scoring, natural-language recommendations (`anomaly_service.py`, `/admin/anomalies`, `/tenant/anomalies`, `AnomalyDashboard.tsx`)

---

## P0 — Security Hardening (must fix before production)

- [ ] **Replace `create_all` with Alembic migrations**
  - `startup()` in `main.py` calls `Base.metadata.create_all` — unsafe in production
  - Add `alembic init alembic`, configure `env.py`, generate initial revision
  - All future schema changes must be migrations, not `create_all`

- [ ] **Rate-limit `/verify-license` properly**
  - Current logic counts raw DB rows (`limit(5)`) but never clears them → blocked forever
  - Implement sliding-window counter (Redis or time-windowed SQL query with `timestamp >= now - 15min`)
  - Add `Retry-After` header on 429

- [ ] **Rotate `OFFLINE_TOKEN_SECRET` independently of `ADMIN_API_KEY`**
  - Currently `OFFLINE_TOKEN_SECRET = ADMIN_API_KEY + "-offline-v1"` if env var not set
  - In production both env vars must be set to independent high-entropy secrets
  - Add startup assertion: `assert len(OFFLINE_TOKEN_SECRET) >= 32`

- [ ] **Validate `ADMIN_API_KEY` is non-empty at startup**
  - Currently an empty key passes `require_admin` if the header is also empty
  - Add startup assertion: `assert ADMIN_API_KEY, "ADMIN_API_KEY must be set"`

- [ ] **Add CORS configuration**
  - `fastapi.middleware.cors.CORSMiddleware` with explicit `allow_origins`
  - Never use `allow_origins=["*"]` in production

- [ ] **HTTPS / TLS enforcement**
  - Deploy behind nginx / Caddy with TLS termination
  - Set `Strict-Transport-Security` header

- [ ] **Store `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` in env vars only**
  - Audit `stripe_service.py` — confirm no hard-coded keys

---

## P1 — Correctness & Reliability

- [ ] **Fix `BOT_THRESHOLD_MS` constant placement**
  - `BOT_THRESHOLD_MS` and `SESSION_ACTIVE_MINUTES` are defined *after* `analytics_start`
  which uses `SESSION_ACTIVE_MINUTES` — move constants to top of file (just after secrets)

- [ ] **`/analytics/start` — license must be paid**
  - Currently any license (paid or not) can open a session
  - Add: `if not license_record.is_paid: raise HTTPException(403, "License not activated")`

- [ ] **`/verify-license` — check `is_paid`**
  - Unpaid licenses currently return `success` if key matches
  - Return 402 or include `is_paid` in response and let client decide

- [ ] **Geofence: handle ip-api.com outage gracefully**
  - `geo_service.get_country_code` returns `"XX"` on error (permissive fallback)
  - Consider making this configurable: `GEO_FAIL_OPEN=true/false` env var

- [ ] **`/admin/proof-of-leak` — unique constraint**
  - Currently a second POST with the same `invoice_id` creates a second report row
  - Consider adding `UNIQUE(invoice_id)` or allowing re-generation with explicit `?force=true`

- [ ] **Offline token: restrict `hours` to a sensible maximum**
  - Add server-side cap: `if hours > 720: raise HTTPException(422, "Max 720 hours (30 days)")`

---

## P2 — Developer Experience

- [ ] **OpenAPI / Swagger UI**
  - FastAPI auto-generates `/docs` and `/redoc` — expose only in `DEBUG` mode in production
  - Add Pydantic response models so the generated schema is accurate (currently returns `dict`)

- [ ] **Add Pydantic request/response models**
  - All endpoints use bare query params and return `dict` — replace with `BaseModel` schemas
  - This enables type-safe clients, proper OpenAPI generation, and input validation

- [ ] **Structured logging**
  - Replace `print`/bare exceptions with `logging` (JSON format in production)
  - Log every admin action with `invoice_id`, `admin_ip`, `timestamp`

- [ ] **`pytest` CI step**
  - Add GitHub Actions workflow: `pytest backend/ -v --tb=short`
  - Run on every push to `main` and on every PR

- [ ] **Environment variable documentation**
  - Create `backend/.env.example` with all required vars and safe defaults
  - `ADMIN_API_KEY`, `OFFLINE_TOKEN_SECRET`, `DATABASE_URL`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `NEXT_PUBLIC_API_URL`

- [ ] **Docker Compose**
  - `docker-compose.yml` with services: `postgres`, `backend`, `frontend`
  - Use `depends_on` and `healthcheck` so backend waits for DB

---

## P3 — Features & Enhancements

- [ ] **License expiry date**
  - Add `expires_at: DateTime` column to `License`
  - `verify-license` and `analytics/start` reject expired licenses with 410 Gone

- [x] **Multi-content support**
  - `LicenseContent` M2M table links `License` ↔ `VaultContent`
  - 4 endpoints: grant/revoke/list per license, list per content item
  - `POST /vault/access/{id}` enforces per-content license check (open if no links)
  - `ContentVault.tsx` shows linked-license count badge + inline grant/revoke panel

- [ ] **Email delivery of license keys**
  - After `create-license`, optionally send the plain key via SendGrid / SES
  - Add `owner_email` column to `License`

- [ ] **Admin TOTP / 2FA**
  - Replace single static `X-Admin-Key` with TOTP-based one-time codes (pyotp)
  - Or issue short-lived admin JWT from a `/admin/login` endpoint (avoids key leakage in headers)

- [ ] **Webhook for geo-block events**
  - When a user is geo-blocked, POST a JSON payload to an admin-configured webhook URL
  - Useful for real-time SIEM / Slack alerting

- [ ] **Bulk license import (CSV)**
  - `POST /admin/licenses/bulk` — upload CSV `invoice_id,owner_id,max_sessions,countries`
  - Return per-row success/failure JSON

- [ ] **Pagination on list endpoints**
  - `/admin/audit-log` (capped at 100 today), `/admin/analytics`, `/admin/offline-tokens`
  - Add `?limit=50&offset=0` query params

- [ ] **Revocation reason on offline tokens**
  - Add `revocation_reason: String nullable` column to `OfflineToken`
  - `DELETE /admin/offline-token/{id}?reason=lost_device`

---

## P4 — Frontend Polish

- [ ] **Dark/light theme toggle** on Admin Dashboard

- [ ] **Offline token QR code**
  - Generate QR code of the JWT string in `OfflineTokenManager`
  - Allows air-gapped delivery by scanning with a mobile device

- [ ] **Live refresh** — poll `/admin/analytics` every 30 s or use WebSocket

- [ ] **Confirm dialog** before Revoke (session and offline token)

- [ ] **i18n** — UI currently mixes English and Russian strings; unify to English

- [ ] **`SecureContent` — show watermark fingerprint** after successful unlock
  - Display the integer fingerprint value returned by `/verify-license` so the user
    knows their copy is watermarked with their identity

---

## Known Technical Debt

| File | Issue |
|---|---|
| `main.py:204` | `BOT_THRESHOLD_MS` defined after first use |
| `main.py:30` | `@app.on_event("startup")` deprecated in FastAPI 0.93+; replace with `lifespan` |
| `main.py:78` | Brute-force window never expires; counts all-time failures |
| `SecureContent.tsx:13` | `viewer` typed as `any` — add Wasm type bindings |
| `AdminDashboard.tsx:21` | `licenses` typed as `any[]` — add `License` interface |
| `conftest.py` | `db_session` fixture recreates all tables per test (slow); consider per-test transaction rollback |
