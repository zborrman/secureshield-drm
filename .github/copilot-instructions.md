# AI Copilot Instructions for SecureShield DRM System

## Architecture Overview

**SecureShield** is an enterprise DRM platform with forensic watermarking, brute-force protection, and offline viewing. Three-layer architecture:

- **Frontend**: Next.js 14 with TypeScript (Server Components preferred), Tailwind CSS
- **Backend**: FastAPI async (SQLAlchemy ORM), PostgreSQL, Redis for sessions  
- **Security Module**: Rust + WebAssembly (wasm-bindgen) for content decryption and anti-capture noise

**Key data flows**:
1. User obtains license → Stripe checkout webhook sets `is_paid=true`
2. License verify endpoint enforces 5-fail/IP brute-force block + audit logs
3. Analytics session: start heartbeat → bot detection (< 500ms) → duration tracking
4. Admin can revoke sessions, geofence by country, issue offline JWT tokens
5. Wasm module gates content decryption behind verified license check

---

## Critical Security Patterns (DO NOT Skip)

- **Every license check must verify `is_paid=true`** — unpaid licenses can be enumerated otherwise
- **Audit logging**: Every verify attempt logged with IP, user-agent, result to `audit_logs` table
- **Fingerprinting**: SHA-256 deterministic fingerprint per user+session, stored in watermark, reversible via admin
- **Geofence**: Dynamic country restriction via `allowed_countries` field (NULL = unrestricted), validated against ip-api.com
- **Offline tokens**: HS256 JWT with client-side expiry check; revocation stored in `offline_tokens.is_revoked`

---

## Database & ORM Conventions

**Key models** in [backend/models.py](backend/models.py#L1-L100):
- `Tenant` — multi-tenant support; each operation filters by `tenant_id`
- `License` — linked to invoice (Stripe); includes `max_sessions`, `allowed_countries`, `is_paid`
- `AuditLog` — immutable append-only for compliance
- `ViewAnalytics` — session tracking; `is_bot_suspect` flag from heartbeat timing
- `OfflineToken` — JWT jti as primary key, server-side revocation list

**Async SQLAlchemy** used throughout: `async with SessionLocal() as session`, `await session.execute(select(...))`, never blocking.

---

## Backend Development (FastAPI)

**All routes** in [backend/main.py](backend/main.py#L1-L50) follow dependency injection:
```python
async def get_db():
    async with SessionLocal() as session:
        yield session

async def require_admin(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(401, "Unauthorized")
```

**Header-based auth**: 
- `X-Admin-Key` for admin endpoints
- `X-Super-Admin-Key` for super-admin (tenant management)
- `X-Tenant-Id` for multi-tenant isolation

**New endpoints must**:
1. Extract tenant from header or derive from license
2. Log to `audit_logs` if security-sensitive
3. Return 402 if unpaid license required, 409 if concurrent session limit hit
4. Use type-hint validation via Pydantic

---

## Frontend Development (Next.js 14)

**App Router structure**: `src/app/(app)/{dashboard,admin,viewer}` for authenticated routes; `src/app/auth/signin` for login.

**Server Components by default** — only mark Client Components (`'use client'`) when state/hooks needed. This minimizes JS bundle size critical for embedded DRM viewer.

**Key components**:
- `SecureContent.tsx` — wrapper that validates license before rendering Wasm player
- `WasmPlayer.tsx` — canvas-based player loading decrypted content from Wasm module
- `AdminDashboard.tsx` — displays `audit_logs`, `view_analytics`, controls revocation/geofence
- `OfflineTokenManager.tsx` — admin interface for issuing offline JWT tokens

**Environment variables** (used in build):
- `NEXT_PUBLIC_API_URL` — backend API base URL
- Wasm bindings auto-imported from `wasm/pkg/`

---

## WebAssembly Integration

**Rust code** ([backend/wasm/src/lib.rs](wasm/src/lib.rs#L1-L50)) exports:
- `SecureViewer::verify_key()` — gates content decryption
- `apply_anti_capture_noise()` — adds per-frame pixel noise
- `decrypt_content()` — XOR stub (real: AES-GCM); returns `ACCESS_DENIED_SECURE_ENCLAVE` if unverified

**Build workflow**:
```bash
cd wasm && wasm-pack build --target web --out-dir ../frontend/wasm/pkg
```
Called via `npm run build-wasm` from frontend.

**Frontend usage**:
```typescript
import init, { SecureViewer } from '../wasm/pkg/wasm';
const viewer = new SecureViewer();
viewer.verify_key(licenseKey);
const decrypted = viewer.decrypt_content(encryptedData);
```

---

## Testing Strategy

**Three test suites** run via [run_tests.sh](run_tests.sh):

1. **Backend (Pytest)**: `docker-compose exec backend pytest tests/ test_security.py -v`
   - Tests in `backend/tests/` cover auth, audit, geofence, bot detection, SQL injection, multitenancy
   - Fixtures in [conftest.py](backend/conftest.py) provide `db`, `client`, `sample_license`
   - Use `@pytest.mark.asyncio` for async tests

2. **Rust/Wasm**: `cd wasm && cargo test`
   - Tests verify key verification, XOR roundtrip, access denial
   - Unit tests in `lib.rs` use `#[cfg(test)]` module

3. **E2E (Playwright)**: `cd frontend && npx playwright test`
   - Specs in [frontend/e2e/](frontend/e2e/) test DRM flow, security stress
   - Runs against live Docker containers; requires `docker-compose up`

**Debugging**:
- Port 8000 (FastAPI) → see OpenAPI docs at `http://localhost:8000/docs`
- Port 3000 (Next.js) → dev server with hot-reload
- Port 5432 (Postgres) → connect via `psql -h localhost -U user -d main_db`

---

## Docker Compose Setup

**Services** ([docker-compose.yml](docker-compose.yml)):
- `db` (Postgres 15) — health check required before backend starts
- `backend` (FastAPI) — port 8001:8000, mounts `./backend:/app` for hot-reload
- `frontend` (Next.js) — port 3000:3000, mounts `./frontend:/app`

**Startup command**:
```bash
docker-compose down  # Clean up old containers
docker-compose up --build  # Build & start
```

**Common issues**:
- Port 8000 already in use: `netstat -ano | findstr :8000` then `taskkill /PID <PID> /F`
- Volume mount permission: WSL2 users ensure docker desktop uses WSL backend

---

## Project-Specific Conventions

1. **Tenant isolation**: Every DB query must filter by `tenant_id` — no shared data across tenants
2. **Error codes**:
   - 401 → auth failure
   - 402 → payment required (unpaid license)
   - 403 → forbidden (e.g., geofence block)
   - 409 → conflict (e.g., session limit exceeded)
3. **Hashing**: Use `auth_utils.hash_license_key()` (bcrypt) for storage; never plaintext
4. **Timestamps**: Always UTC (`datetime.utcnow()`); store in `DateTime` columns
5. **Environment**: Never hardcode keys — all secrets via `.env` file

---

## Known Limitations & TODOs

- **Migrations**: Currently uses `Base.metadata.create_all()` at startup → migrate to Alembic for production
- **Rate limiting**: Sliding-window counter for verify endpoint not yet implemented (P0 security issue)
- **Geofence fallback**: ip-api.com outage returns "XX" (permissive) — consider `GEO_FAIL_OPEN` env var
- **Bot threshold**: `BOT_THRESHOLD_MS = 500ms` configurable via constants; consider moving to config table

---

## Useful File References

| File | Purpose |
|------|---------|
| [backend/main.py](backend/main.py) | All API routes, auth, analytics, audit logging |
| [backend/models.py](backend/models.py) | SQLAlchemy ORM schemas |
| [backend/stripe_service.py](backend/stripe_service.py) | Stripe checkout & webhook handling |
| [frontend/src/components/SecureContent.tsx](frontend/src/components/SecureContent.tsx) | License validation before rendering |
| [wasm/src/lib.rs](wasm/src/lib.rs) | Rust DRM logic exported to JS |
| [openapi.yaml](openapi.yaml) | API spec (auto-generated from FastAPI) |

---

## When in Doubt

1. Check [TESTING.md](TESTING.md) for step-by-step test runs
2. Review [TODO.md](TODO.md) for known issues and security gaps
3. Run `docker-compose exec backend pytest tests/ -v` before committing
4. Always validate unpaid licenses cannot access content (P0 security pattern)
