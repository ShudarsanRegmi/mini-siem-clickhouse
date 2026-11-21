"""
End-to-End (E2E) Lifecycle Test Suite.
Simulates full multi-stage pipeline across all tiers:
 1. Ingestion: Forward telemetry and posture findings via authenticated Gateway API.
 2. ClickHouse Engine: Validate event persistence and ReplacingMergeTree view.
 3. Detection Simulation: Execute detection correlation query against raw telemetry.
 4. Alert Record: Write alert into security_alerts.
 5. Dashboard Consumption: Verify that read-only Grafana viewer role can query the alert and posture state.
"""

import uuid
import datetime
import json
import pytest
from src.common.db import get_db_client


@pytest.mark.e2e
def test_end_to_end_siem_workflow(api_client, valid_bearer_token):
    target_vm_id = f"e2e-target-vm-{uuid.uuid4().hex[:6]}"
    simulated_attack_cmd = "cat /etc/shadow | grep root"

    # Step 1: Ingest Telemetry via Authenticated Gateway (Simulating VM Attack Activity)
    attack_event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "asset_type": "vm",
        "asset_id": target_vm_id,
        "event_category": "auth",
        "event_type": "sensitive_file_read",
        "severity": "CRITICAL",
        "actor": "attacker_user",
        "source_ip": "10.0.0.99",
        "process_name": "cat",
        "command_line": simulated_attack_cmd,
        "target_resource": "/etc/shadow",
        "raw_json": json.dumps({"tty": "pts/0", "uid": 1001, "euid": 0}),
    }

    res_telemetry = api_client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[attack_event],
    )
    assert res_telemetry.status_code == 201

    # Step 2: Ingest Posture Finding via Authenticated Gateway (Simulating VM Vulnerability Scan)
    posture_check_id = f"CIS-LINUX-{uuid.uuid4().hex[:4].upper()}"
    posture_finding = {
        "asset_type": "vm",
        "asset_id": target_vm_id,
        "scanner_tool": "lynis",
        "finding_type": "misconfiguration",
        "check_id": posture_check_id,
        "title": "Permissive File Permissions on /etc/shadow",
        "severity": "CRITICAL",
        "status": "OPEN",
        "remediation": "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow",
        "details": "World-readable shadow file detected during host compliance scan",
    }

    res_posture = api_client.post(
        "/api/v1/posture",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[posture_finding],
    )
    assert res_posture.status_code == 201

    # Step 3: Run Detection Engine Query (Using detector role)
    detector_client = get_db_client(role="detector")
    detection_sql = f"""
    SELECT
        asset_type,
        asset_id,
        actor,
        command_line,
        target_resource
    FROM siem.raw_telemetry
    WHERE asset_id = '{target_vm_id}'
      AND target_resource = '/etc/shadow'
      AND actor != 'root'
    LIMIT 1;
    """
    matched = detector_client.query(detection_sql).result_rows
    assert len(matched) == 1, "Detection rule failed to identify simulated credential access attack"

    # Step 4: Write Detection Alert into security_alerts (Using detector role)
    alert_id = uuid.uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)
    detector_client.insert(
        "security_alerts",
        [[
            alert_id,
            now,
            "SEC-VM-001",
            "Credential Access: Unauthorized /etc/shadow Access",
            "Credential Access",
            "T1003.008",
            "vm",
            target_vm_id,
            "CRITICAL",
            1,
            f"Unauthorized user '{matched[0][2]}' attempted sensitive file access via '{matched[0][3]}'",
            json.dumps({"target": matched[0][4], "cmd": matched[0][3]}),
            "Excluded legitimate system PAM processes login/passwd",
        ]],
        column_names=[
            "alert_id", "triggered_at", "rule_id", "rule_name",
            "mitre_tactic", "mitre_technique", "asset_type", "asset_id",
            "severity", "matched_events_count", "alert_description",
            "evidence_context", "false_positive_tuning_notes"
        ],
    )

    # Step 5: Verify Grafana Read-Only Viewer can query both Posture and the Fired Alert
    viewer_client = get_db_client(role="viewer")

    # 5a. Query Alert
    alerts = viewer_client.query(
        f"SELECT rule_name, severity, asset_id FROM siem.security_alerts WHERE alert_id = '{alert_id}'"
    ).result_rows
    assert len(alerts) == 1
    assert alerts[0][0] == "Credential Access: Unauthorized /etc/shadow Access"
    assert alerts[0][1] == "CRITICAL"
    assert alerts[0][2] == target_vm_id

    # 5b. Query Posture Finding
    posture_res = viewer_client.query(
        f"SELECT title, severity, status FROM siem.v_latest_posture WHERE asset_id = '{target_vm_id}' AND check_id = '{posture_check_id}'"
    ).result_rows
    assert len(posture_res) == 1
    assert posture_res[0][0] == "Permissive File Permissions on /etc/shadow"
    assert posture_res[0][1] == "CRITICAL"
    assert posture_res[0][2] == "OPEN"
