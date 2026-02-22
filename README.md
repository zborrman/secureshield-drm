# SecureShield DRM System

Enterprise-grade Digital Rights Management platform with multi-tenant SaaS support,
forensic watermarking, AI anomaly detection, geofencing, offline tokens, and
AES-256-GCM encrypted content vault.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy 2 (async), PostgreSQL / SQLite |
| Frontend | Next.js 14 App Router, TypeScript, Tailwind CSS |
| Security Module | Rust + WebAssembly (wasm-bindgen) |
| Payments | Stripe Checkout + Webhooks |
| Auth | bcrypt (passlib), PyJWT (HS256) |
| Cache / Events | Redis (session revocation, SSE pub/sub) |
| Storage | AWS S3 (encrypted vault, AES-256-GCM) |
| Containerization | Docker Compose |

---

## Quick Start

```bash
# 1. Copy environment template and fill in your secrets
cp .env.example .env

# 2. Start all services
docker-compose up --build

# 3. Run the test suite
cd backend && pytest tests/ -v --tb=short
```

After startup:

| Service | URL |
|---|---|
| Frontend (viewer) | http://localhost:3000 |
| Admin Dashboard | http://localhost:3000/admin |
| Tenant Dashboard | http://localhost:3000/tenant |
| Super-Admin Dashboard | http://localhost:3000/superadmin |
| API (Swagger) | http://localhost:8000/docs |
| API (ReDoc) | http://localhost:8000/redoc |

---

## Authentication Model

SecureShield uses a **3-tier auth model**. Every request must include the correct header for its tier.

| Tier | Header | Used for |
|---|---|---|
| **Public** | *(none)* | `/verify-license`, `/analytics/*`, Stripe webhook |
| **Admin** | `X-Admin-Key: <ADMIN_API_KEY>` | `/admin/*` — full platform management |
| **Tenant-admin** | `X-Tenant-ID: <slug>` + `X-Admin-Key: <tenant_key>` | `/tenant/*` — scoped to one tenant |
| **Super-admin** | `X-Super-Admin-Key: <SUPER_ADMIN_KEY>` | `/superadmin/*` — tenant provisioning |

---

## API Endpoints

### Public (no auth required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/verify-license` | Verify license key (brute-force + geo protected) |
| `POST` | `/signout` | Log signout event |
| `POST` | `/verify-offline-token` | Validate an offline JWT |
| `POST` | `/create-checkout-session` | Create Stripe checkout session |
| `POST` | `/webhook/stripe` | Stripe event handler |
| `POST` | `/analytics/start` | Start a viewing session |
| `POST` | `/analytics/heartbeat/{session_id}` | Session heartbeat |

### Admin (`X-Admin-Key` required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (DB + Redis + S3) |
| `POST` | `/admin/create-license` | Create a license |
| `GET` | `/admin/licenses` | List all licenses |
| `PATCH` | `/admin/licenses/{invoice_id}/geo` | Update geofence |
| `GET` | `/admin/audit-log` | Full audit trail |
| `GET` | `/admin/alerts` | Recent failed attempts |
| `GET` | `/admin/analytics` | Viewing sessions |
| `DELETE` | `/admin/analytics/{session_id}` | Revoke a session |
| `GET` | `/admin/sessions/live` | Active sessions (Redis) |
| `POST` | `/admin/sessions/revoke-all/{invoice_id}` | Kill all sessions for a license |
| `GET` | `/admin/events` | SSE stream for live revocations |
| `POST` | `/admin/proof-of-leak` | Generate tamper-evident leak report |
| `GET` | `/admin/proof-of-leak` | List leak reports |
| `GET` | `/admin/proof-of-leak/{report_id}` | Get a specific report |
| `POST` | `/admin/offline-token` | Issue an offline JWT |
| `DELETE` | `/admin/offline-token/{token_id}` | Revoke an offline token |
| `GET` | `/admin/offline-tokens` | List offline tokens |
| `POST` | `/admin/vault/upload` | Upload encrypted content |
| `GET` | `/admin/vault/contents` | List vault items |
| `DELETE` | `/admin/vault/{content_id}` | Delete vault item |
| `POST` | `/admin/vault/{content_id}/grant/{invoice_id}` | Grant content to a license |
| `DELETE` | `/admin/vault/{content_id}/grant/{invoice_id}` | Revoke content grant |
| `GET` | `/admin/vault/{content_id}/licenses` | Licenses with access to content |
| `GET` | `/admin/vault/stream/{access_token}` | Stream decrypted content |
| `GET` | `/admin/anomalies` | AI anomaly analysis |
| `GET` | `/admin/anomalies/summary` | Anomaly summary widget |
| `GET` | `/admin/gdpr/export/{invoice_id}` | GDPR Subject Access Request export |
| `DELETE` | `/admin/gdpr/purge/{invoice_id}` | GDPR right-to-be-forgotten |

### Tenant (`X-Tenant-ID` + `X-Admin-Key` required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/tenant/licenses` | Create license (plan-limited) |
| `GET` | `/tenant/licenses` | List tenant licenses |
| `GET` | `/tenant/audit-log` | Tenant audit log |
| `GET` | `/tenant/analytics` | Tenant analytics |
| `GET` | `/tenant/alerts` | Tenant recent failures |
| `POST` | `/tenant/offline-token` | Issue offline token |
| `GET` | `/tenant/offline-tokens` | List offline tokens |
| `DELETE` | `/tenant/offline-token/{token_id}` | Revoke offline token |
| `POST` | `/tenant/vault/upload` | Upload to tenant vault partition |
| `GET` | `/tenant/vault/contents` | List tenant vault items |
| `DELETE` | `/tenant/vault/{content_id}` | Delete tenant vault item |
| `GET` | `/tenant/anomalies` | AI anomaly analysis (tenant-scoped) |

### Super-Admin (`X-Super-Admin-Key` required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/superadmin/tenants` | Provision a new tenant |
| `GET` | `/superadmin/tenants` | List all tenants |
| `PATCH` | `/superadmin/tenants/{slug}` | Update tenant plan/limits |
| `DELETE` | `/superadmin/tenants/{slug}` | Delete tenant and all data |

---

## Environment Variables

See [`.env.example`](.env.example) for the full annotated reference. Minimum required:

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | SQLAlchemy async connection string |
| `ADMIN_API_KEY` | Yes | Admin API key (≥32 chars recommended) |
| `OFFLINE_TOKEN_SECRET` | Yes | JWT signing secret for offline tokens (**≥32 bytes**) |
| `VAULT_TOKEN_SECRET` | Yes | JWT signing secret for vault access tokens (**≥32 bytes**) |
| `VAULT_MASTER_KEY` | Yes | Base64-encoded 32-byte key for AES key wrapping |
| `SUPER_ADMIN_KEY` | Yes | Super-admin key for tenant provisioning |
| `REDIS_URL` | Yes | Redis connection string |
| `STRIPE_API_KEY` | Payments | Stripe secret key |
| `STRIPE_WEBHOOK_SECRET` | Payments | Stripe webhook signing secret |
| `AWS_ACCESS_KEY_ID` | Vault | S3 credentials |
| `AWS_SECRET_ACCESS_KEY` | Vault | S3 credentials |
| `S3_BUCKET` | Vault | S3 bucket name (default: `secureshield-vault`) |
| `CORS_ORIGINS` | Prod | Comma-separated allowed origins |

---

## Project Structure

```
SecureShield DRM System/
├── backend/
│   ├── main.py                 # App factory, middleware, lifecycle
│   ├── config.py               # All env-vars and constants (single source of truth)
│   ├── schemas.py              # Pydantic request/response models
│   ├── models.py               # SQLAlchemy models
│   ├── database.py             # Async engine + session factory
│   ├── dependencies.py         # Shared FastAPI deps (get_db, require_admin, …)
│   ├── auth_utils.py           # bcrypt hashing helpers
│   ├── watermark_service.py    # SHA-256 forensic fingerprinting
│   ├── stripe_service.py       # Stripe integration
│   ├── redis_service.py        # Redis session management + SSE
│   ├── vault_service.py        # AES-256-GCM encryption + S3
│   ├── geo_service.py          # IP geolocation (ip-api.com)
│   ├── anomaly_service.py      # 7-detector AI anomaly engine
│   ├── rate_limit.py           # slowapi Limiter with per-role limits
│   ├── routers/
│   │   ├── auth.py             # Public routes
│   │   ├── admin.py            # Admin routes
│   │   ├── vault.py            # Admin vault routes
│   │   ├── tenant.py           # Tenant-scoped routes
│   │   └── superadmin.py       # Super-admin routes
│   ├── migrations/             # Alembic async migrations
│   ├── tests/                  # pytest test suite (78 tests)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── (app)/admin/page.tsx
│   │   │   ├── (app)/tenant/page.tsx
│   │   │   └── (app)/superadmin/page.tsx
│   │   └── components/
│   │       ├── AdminDashboard.tsx
│   │       ├── TenantDashboard.tsx
│   │       ├── SuperAdminDashboard.tsx
│   │       ├── AnomalyDashboard.tsx
│   │       └── ContentVault.tsx
│   ├── package.json
│   └── Dockerfile
├── wasm/
│   ├── src/lib.rs              # Rust DRM primitives
│   └── Cargo.toml
├── .env.example                # Annotated environment variable reference
├── docker-compose.yml
└── .gitignore
```

---

## Security Features

| Feature | Detail |
|---|---|
| **Brute-force protection** | Sliding 15-min window; blocks after 5 failures per IP |
| **Forensic watermarking** | SHA-256 owner fingerprint embedded per session |
| **Geofencing** | Per-license country whitelist via ip-api.com |
| **Session orchestration** | Real-time revocation via Redis + SSE push |
| **Offline tokens** | HS256 JWT with `jti` revocation list; ≤7 days |
| **Content vault** | Per-file AES-256-GCM; key wrapped with Fernet (VAULT_MASTER_KEY) |
| **Multi-tenancy** | Shared schema; tenant auth via bcrypt-hashed admin key |
| **AI anomaly detection** | 7-detector heuristic engine (IP velocity, bot pattern, geo spread, …) |
| **Rate limiting** | Per-role slowapi limits; disabled in tests via `RATE_LIMIT_ENABLED=false` |
| **Security headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy on every response |
| **Startup validation** | Server refuses to start with weak/missing secrets |

---

## Running Tests

```bash
cd backend
pytest tests/ -v --tb=short
```

Tests use SQLite (aiosqlite), fakeredis, and moto (mock S3). No external services required.

---

## Database Migrations

```bash
# Apply all migrations
cd backend && alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "describe your change"

# Roll back one step
alembic downgrade -1
```

---

## Key Rotation Guide

### Rotating `ADMIN_API_KEY`

Zero-downtime rotation:
1. Add the new key as a second accepted value in `dependencies.py` → `require_admin`
2. Deploy and notify all admin clients to update their key
3. Remove the old key from `dependencies.py` and redeploy

### Rotating `VAULT_MASTER_KEY`

Requires re-encryption — all vault files must be re-wrapped:
1. Export `VAULT_MASTER_KEY_OLD=<current>`, `VAULT_MASTER_KEY=<new>`
2. Run the re-wrap migration script (not yet included — open a GitHub issue if needed)
3. Redeploy

### Rotating `OFFLINE_TOKEN_SECRET`

All existing offline tokens become invalid immediately after rotation. Warn users before rotating.

---

## GDPR Compliance

| Requirement | Endpoint |
|---|---|
| Subject Access Request (export) | `GET /admin/gdpr/export/{invoice_id}` |
| Right to be forgotten (purge) | `DELETE /admin/gdpr/purge/{invoice_id}` |

Purging removes: audit log entries, view analytics, offline tokens, vault grants, and the license record itself. The purge is permanent and cannot be undone.
