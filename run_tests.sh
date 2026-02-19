#!/bin/bash
set -e  # Stop on first failure

echo "======================================================"
echo "  SecureShield DRM — Full System Audit"
echo "======================================================"

# ── 1. Backend + Database ──────────────────────────────
echo ""
echo "--- [1/3] Testing Backend & Database ---"
docker-compose exec backend pytest tests/ test_security.py -v
echo "✓ Backend tests passed"

# ── 2. Rust / Wasm ────────────────────────────────────
echo ""
echo "--- [2/3] Testing Rust/Wasm Logic ---"
cd wasm && cargo test && cd ..
echo "✓ Rust/Wasm tests passed"

# ── 3. Playwright E2E ─────────────────────────────────
echo ""
echo "--- [3/3] Running E2E Playwright Tests ---"
cd frontend && npx playwright test
echo "✓ E2E tests passed"

echo ""
echo "======================================================"
echo "  All tests passed. System is production-ready."
echo "======================================================"
