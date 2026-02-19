# SecureShield DRM System

Enterprise-grade Digital Rights Management platform with forensic watermarking, brute-force protection, Stripe payments, and WebAssembly content protection.

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | FastAPI, SQLAlchemy (async), PostgreSQL |
| Security Module | Rust + WebAssembly (wasm-bindgen) |
| Payments | Stripe Checkout + Webhooks |
| Auth | bcrypt (passlib), PyJWT |
| Containerization | Docker Compose |

## Quick Start

```bash
# Copy environment file and fill in your keys
cp .env.example .env

# Build and start all services
docker-compose up --build
```

## Component Addresses

| Component | URL |
|---|---|
| User Interface | http://localhost:3000 |
| Admin Dashboard | http://localhost:3000/admin |
| API Documentation | http://localhost:8000/docs |

## Project Structure

```
SecureShield DRM System/
├── backend/
│   ├── main.py              # FastAPI app, all routes
│   ├── models.py            # License + AuditLog models
│   ├── database.py          # Async SQLAlchemy engine
│   ├── auth_utils.py        # bcrypt hashing
│   ├── watermark_service.py # SHA-256 fingerprinting
│   ├── stripe_service.py    # Stripe integration
│   ├── conftest.py          # pytest fixtures
│   ├── test_security.py     # Integration tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx         # Main viewer
│   │   │   └── admin/page.tsx   # Admin route
│   │   └── components/
│   │       ├── SecureContent.tsx   # Wasm content viewer
│   │       ├── WasmPlayer.tsx      # Canvas-based player
│   │       └── AdminDashboard.tsx  # Admin panel
│   ├── package.json
│   └── Dockerfile
├── wasm/
│   ├── src/lib.rs    # Rust DRM logic
│   └── Cargo.toml
├── docker-compose.yml
├── .env              # Secrets (never commit)
└── .gitignore
```

## Security Features

- **Brute-force protection** — 429 after 5 failed attempts per IP
- **Forensic watermarking** — SHA-256 user fingerprint embedded per session
- **Anti-screenshot noise** — per-frame pixel noise via Rust/Wasm
- **Audit trail** — every verify attempt logged (IP, user-agent, result)
- **bcrypt hashing** — license keys never stored in plaintext

## Running Tests

```bash
docker-compose exec backend pytest test_security.py -v
```

## Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `STRIPE_API_KEY` | Stripe secret key (`sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (`whsec_...`) |
