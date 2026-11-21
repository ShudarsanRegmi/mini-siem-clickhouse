"""
Pytest configuration and shared test fixtures for Mini SIEM test suite.
Supports Unit, Integration, Security, and E2E testing tiers.
"""

import os
import sys
import hmac
import hashlib
import json
import datetime
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure repo root is always in python path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file, get_db_client
from src.ingestion.collector import app, BEARER_TOKEN, GITHUB_SECRET

load_env_file()


@pytest.fixture(scope="session")
def api_client():
    """Shared FastAPI test client for HTTP endpoint tests."""
    return TestClient(app)


@pytest.fixture(scope="session")
def valid_bearer_token():
    """Returns the configured ingestion bearer token."""
    return BEARER_TOKEN


@pytest.fixture(scope="session")
def github_webhook_secret():
    """Returns the shared webhook HMAC secret."""
    return GITHUB_SECRET


@pytest.fixture
def make_github_signature():
    """Helper factory to generate HMAC-SHA256 signatures for webhook payloads."""
    def _signer(payload_bytes: bytes, secret: str = GITHUB_SECRET) -> str:
        return "sha256=" + hmac.new(
            secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
    return _signer


@pytest.fixture
def sample_telemetry_event():
    """Generates a valid sample telemetry event dictionary."""
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "asset_type": "laptop",
        "asset_id": "test-workstation-01",
        "event_category": "process",
        "event_type": "process_spawn",
        "severity": "INFO",
        "actor": "sec_analyst",
        "source_ip": "192.168.1.105",
        "process_name": "python3",
        "command_line": "python3 -m pytest",
        "target_resource": "/usr/bin/python3",
        "raw_json": json.dumps({"source": "pytest", "env": "testing"}),
    }


@pytest.fixture
def sample_posture_finding():
    """Generates a valid sample posture finding dictionary."""
    return {
        "asset_type": "vm",
        "asset_id": "prod-web-vm-01",
        "scanner_tool": "trivy",
        "finding_type": "vulnerability",
        "check_id": f"CVE-2024-{uuid.uuid4().hex[:6].upper()}",
        "title": "OpenSSL Buffer Overflow Vulnerability",
        "severity": "HIGH",
        "status": "OPEN",
        "remediation": "Upgrade libssl3 to >= 3.0.13",
        "details": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }
