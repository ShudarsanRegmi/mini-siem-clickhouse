"""
Security Assurance Tests: Authentication, Token Verification & HMAC Signatures.
Verifies fail-secure behavior, token validation, tamper detection, and DoS protections.
"""

import json
import pytest


@pytest.mark.security
def test_unauthenticated_request_rejected(api_client):
    """Fail-Secure: API must reject unauthenticated requests with 401."""
    res = api_client.post("/api/v1/telemetry", json=[])
    assert res.status_code == 401
    assert "Missing or invalid Authorization" in res.json()["detail"]


@pytest.mark.security
def test_invalid_bearer_token_rejected(api_client):
    """Defense in Depth: Invalid bearer token must return 403 Forbidden."""
    res = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": "Bearer fraudulent_token_attack"},
        json=[],
    )
    assert res.status_code == 403
    assert "Invalid credentials" in res.json()["detail"]


@pytest.mark.security
def test_empty_batch_rejected(api_client, valid_bearer_token):
    """Input Validation: Empty payloads must be rejected with 400 Bad Request."""
    res = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[],
    )
    assert res.status_code == 400
    assert "Empty telemetry payload" in res.json()["detail"]


@pytest.mark.security
def test_oversized_payload_rejected_dos_protection(api_client, valid_bearer_token):
    """DoS Mitigation: Batches exceeding 5,000 items must be rejected with 413."""
    oversized = [{
        "asset_type": "laptop",
        "asset_id": "host-dos",
        "event_category": "flood",
        "event_type": "probe",
    }] * 5001

    res = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=oversized,
    )
    assert res.status_code == 413
    assert "exceeds maximum limit" in res.json()["detail"]


@pytest.mark.security
def test_github_webhook_missing_hmac_rejected(api_client):
    """Fail-Secure: Webhook calls without signature must be rejected immediately."""
    res = api_client.post(
        "/api/v1/webhooks/github",
        headers={"X-GitHub-Event": "push"},
        json={"action": "test"},
    )
    assert res.status_code == 401
    assert "Missing or invalid X-Hub-Signature-256" in res.json()["detail"]


@pytest.mark.security
def test_github_webhook_tampered_hmac_rejected(api_client):
    """Cryptographic Verification: Reject forged or tampered signatures."""
    payload = json.dumps({"action": "push", "repository": {"full_name": "corp/repo"}}).encode("utf-8")
    forged_sig = "sha256=" + "f" * 64

    res = api_client.post(
        "/api/v1/webhooks/github",
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": forged_sig,
            "Content-Type": "application/json",
        },
        content=payload,
    )
    assert res.status_code == 401
    assert "Invalid webhook signature" in res.json()["detail"]
