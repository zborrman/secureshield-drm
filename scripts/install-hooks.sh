#!/usr/bin/env bash
# ── Install Docker pre-commit hooks ───────────────────────────────────────────
# Run once per clone to activate the tracked hooks in .githooks/.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

git config core.hooksPath .githooks

echo "✔  Git hooks installed."
echo "   .githooks/pre-commit will now run automatically before every commit"
echo "   that touches a Dockerfile."
echo ""
echo "   Optional: install trivy for CVE scanning"
echo "   https://trivy.dev/latest/getting-started/installation/"
