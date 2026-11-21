#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export PYTHONPATH="$REPO_ROOT"

echo "=== [1/5] Checking Container Health ==="
docker compose ps

echo "=== [2/5] Initializing Database & Least-Privilege RBAC Users ==="
.venv/bin/python scripts/init_db.py

echo "=== [3/5] Running Unit Test Suite ==="
.venv/bin/pytest tests/unit -v

echo "=== [4/5] Running Integration & Security Test Suites ==="
.venv/bin/pytest tests/integration tests/security -v

echo "=== [5/5] Running End-to-End (E2E) Full SIEM Lifecycle Test ==="
.venv/bin/pytest tests/e2e -v

echo ""
echo "================================================================="
echo "  All Test Tiers (Unit, Integration, Security, E2E) Passed!     "
echo "================================================================="
