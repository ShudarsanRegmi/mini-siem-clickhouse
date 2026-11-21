#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export PYTHONPATH="$REPO_ROOT"

echo "=== [1/4] Checking Container Health ==="
docker compose ps

echo "=== [2/4] Initializing Database & Least-Privilege RBAC Users ==="
.venv/bin/python scripts/init_db.py

echo "=== [3/4] Running ClickHouse RBAC Security Test Suite ==="
.venv/bin/pytest tests/test_clickhouse_security.py -v

echo "=== [4/4] Running Ingestion Gateway Security Test Suite ==="
.venv/bin/pytest tests/test_ingestion_security.py -v

echo "=== Phase 1 Security Verification Passed Cleanly ==="
