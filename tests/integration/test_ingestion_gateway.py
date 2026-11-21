"""
Integration Tests: Ingestion Gateway Endpoints.
Tests API functionality, payload acceptance, and database persistence.
Requires running ClickHouse instance.
"""

import json
import pytest


@pytest.mark.integration
def test_gateway_health(api_client):
    """Verify /health endpoint returns healthy status and timestamp."""
    res = api_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


@pytest.mark.integration
def test_telemetry_ingestion_success(api_client, valid_bearer_token, sample_telemetry_event):
    """Verify authenticated telemetry batch is accepted and inserted into ClickHouse."""
    res = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[sample_telemetry_event],
    )
    assert res.status_code == 201
    data = res.json()
    assert data["inserted"] == 1
    assert data["status"] == "success"


@pytest.mark.integration
def test_posture_ingestion_success(api_client, valid_bearer_token, sample_posture_finding):
    """Verify authenticated posture findings batch is accepted and inserted into ClickHouse."""
    res = api_client.post(
        "/api/v1/posture",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[sample_posture_finding],
    )
    assert res.status_code == 201
    data = res.json()
    assert data["inserted"] == 1
    assert data["status"] == "success"


@pytest.mark.integration
def test_github_webhook_authenticated_push(api_client, make_github_signature):
    """Verify authenticated GitHub push webhook payload is processed and stored."""
    payload = json.dumps({
        "ref": "refs/heads/main",
        "repository": {"full_name": "corp/security-service"},
        "sender": {"login": "dev_engineer"},
        "commits": [{"id": "c1a2b3", "message": "feat: update firewall configs"}],
    }).encode("utf-8")

    sig = make_github_signature(payload)
    res = api_client.post(
        "/api/v1/webhooks/github",
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
        content=payload,
    )
    assert res.status_code == 202
    assert res.json()["received"] is True
    assert res.json()["event"] == "push"
    assert res.json()["repo"] == "corp/security-service"
