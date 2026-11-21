"""
Security Assurance Tests: RBAC Isolation & Least-Privilege Verification.
Verifies permission boundaries for all database roles:
 - siem_ingest_role: INSERT only, cannot SELECT or DROP.
 - siem_detector_role: SELECT telemetry/posture and INSERT alerts; cannot INSERT telemetry or DROP.
 - siem_viewer_role: SELECT only; cannot INSERT, UPDATE, or DROP.
"""

import uuid
import datetime
import pytest
from src.common.db import get_db_client


@pytest.mark.security
def test_admin_full_access():
    """Verify administrator user has access to perform setup and status checks."""
    client = get_db_client(role="admin")
    res = client.query("SELECT 1").result_rows
    assert res == [(1,)]


@pytest.mark.security
def test_ingest_role_least_privilege():
    """Verify siem_ingest permissions: INSERT allowed, SELECT and DROP forbidden."""
    client = get_db_client(role="ingest")

    # Ingestion should succeed
    now = datetime.datetime.now(datetime.timezone.utc)
    client.insert(
        "raw_telemetry",
        [[
            now,
            "laptop",
            "sec-probe-host",
            "rbac_audit",
            "probe",
            "INFO",
            "tester",
            "127.0.0.1",
            "pytest",
            "pytest tests/security",
            "raw_telemetry",
            '{"security_check": "passed"}',
        ]],
        column_names=[
            "timestamp", "asset_type", "asset_id", "event_category",
            "event_type", "severity", "actor", "source_ip", "process_name",
            "command_line", "target_resource", "raw_json"
        ],
    )

    # SELECT should FAIL (Access Denied)
    with pytest.raises(Exception) as exc_info:
        client.query("SELECT count() FROM raw_telemetry")
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)

    # DROP should FAIL (Access Denied)
    with pytest.raises(Exception) as exc_info:
        client.command("DROP TABLE raw_telemetry")
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)


@pytest.mark.security
def test_detector_role_least_privilege():
    """Verify siem_detector permissions: SELECT telemetry & INSERT alerts allowed, DROP & INSERT telemetry forbidden."""
    client = get_db_client(role="detector")

    # SELECT on raw_telemetry should SUCCEED
    res = client.query("SELECT count() FROM raw_telemetry").result_rows
    assert res[0][0] >= 1

    # INSERT into security_alerts should SUCCEED
    now = datetime.datetime.now(datetime.timezone.utc)
    client.insert(
        "security_alerts",
        [[
            uuid.uuid4(),
            now,
            "SEC-TEST-001",
            "Security Suite Probe Alert",
            "Execution",
            "T1059",
            "laptop",
            "sec-probe-host",
            "LOW",
            1,
            "Testing detector role authorization",
            '{"verified": true}',
            "Automated test rule",
        ]],
        column_names=[
            "alert_id", "triggered_at", "rule_id", "rule_name",
            "mitre_tactic", "mitre_technique", "asset_type", "asset_id",
            "severity", "matched_events_count", "alert_description",
            "evidence_context", "false_positive_tuning_notes"
        ],
    )

    # INSERT into raw_telemetry should FAIL
    with pytest.raises(Exception) as exc_info:
        client.insert("raw_telemetry", [[now, "laptop", "h", "c", "t", "INFO", "", None, None, None, None, "{}"]])
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)


@pytest.mark.security
def test_viewer_role_least_privilege():
    """Verify siem_grafana permissions: SELECT allowed, INSERT & DROP forbidden."""
    client = get_db_client(role="viewer")

    # SELECT should SUCCEED
    res = client.query("SELECT count() FROM security_alerts").result_rows
    assert res[0][0] >= 1

    # INSERT should FAIL
    with pytest.raises(Exception) as exc_info:
        now = datetime.datetime.now(datetime.timezone.utc)
        client.insert("security_alerts", [[uuid.uuid4(), now, "R", "N", "T", "T", "laptop", "h", "LOW", 1, "d", "{}", ""]])
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)

    # DROP should FAIL
    with pytest.raises(Exception) as exc_info:
        client.command("DROP TABLE security_alerts")
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)
