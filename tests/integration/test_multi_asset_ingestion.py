"""
Integration Test: Multi-Asset Telemetry Ingestion (All 4 Asset Types).
Verifies that the SIEM receives, normalizes, and indexes security telemetry
from all required asset types:
 1. Laptop / Host Workstation
 2. Linux Virtual Machine
 3. Kubernetes Cluster
 4. GitHub Repository
"""

import uuid
import datetime
import pytest
from src.common.db import get_db_client


@pytest.mark.integration
def test_all_four_asset_types_present(api_client, valid_bearer_token, make_github_signature):
    """
    Ingest a tagged telemetry event from each of the 4 asset types,
    then query ClickHouse to verify coverage across all 4 asset classes.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    session_id = uuid.uuid4().hex[:6]

    # 1. Laptop Event
    laptop_event = {
        "timestamp": now,
        "asset_type": "laptop",
        "asset_id": f"laptop-{session_id}",
        "event_category": "process",
        "event_type": "process_spawn",
        "severity": "INFO",
        "actor": "developer_alice",
        "command_line": "git commit -m 'feat: update SIEM forwarders'",
    }

    # 2. Linux VM Event
    vm_event = {
        "timestamp": now,
        "asset_type": "vm",
        "asset_id": f"vm-{session_id}",
        "event_category": "auth",
        "event_type": "ssh_login_success",
        "severity": "INFO",
        "actor": "admin_bob",
        "source_ip": "10.0.1.25",
        "command_line": "sshd: admin_bob [priv]",
    }

    # 3. Kubernetes Event
    k8s_event = {
        "timestamp": now,
        "asset_type": "k8s",
        "asset_id": f"k8s-{session_id}",
        "event_category": "k8s_audit",
        "event_type": "create_pods",
        "severity": "INFO",
        "actor": "system:serviceaccount:default:deployer",
        "command_line": "K8s API CREATE default/pods/api-gateway",
        "target_resource": "default/pods/api-gateway",
    }

    # Send Laptop, VM, and K8s batches via Bearer-authenticated gateway
    res_batch = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[laptop_event, vm_event, k8s_event],
    )
    assert res_batch.status_code == 201

    # 4. GitHub Event via HMAC-authenticated webhook
    import json
    github_payload = json.dumps({
        "ref": "refs/heads/main",
        "repository": {"full_name": f"org/repo-{session_id}"},
        "sender": {"login": "charlie_maintainer"},
        "action": "push",
    }).encode("utf-8")
    sig = make_github_signature(github_payload)

    res_gh = api_client.post(
        "/api/v1/webhooks/github",
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
        content=github_payload,
    )
    assert res_gh.status_code == 202

    # Query ClickHouse to verify all 4 asset_types were stored
    db_client = get_db_client(role="detector")
    res = db_client.query(
        f"""
        SELECT DISTINCT asset_type
        FROM siem.raw_telemetry
        WHERE asset_id LIKE '%{session_id}%'
        ORDER BY asset_type ASC;
        """
    ).result_rows

    found_assets = [r[0] for r in res]
    expected_assets = ["laptop", "vm", "k8s", "github"]

    for exp in expected_assets:
        assert exp in found_assets, f"Asset type '{exp}' was not ingested into ClickHouse"
