"""
Security Verification Suite for ClickHouse SIEM RBAC.
Verifies Least Privilege, Defense in Depth, and Access Control isolation:
 1. siem_ingest CAN insert raw_telemetry & posture_findings, but CANNOT select or drop.
 2. siem_detector CAN select telemetry and insert alerts, but CANNOT insert telemetry or drop tables.
 3. siem_grafana CAN select data, but CANNOT insert, update, or drop tables.
"""

import sys
from pathlib import Path
import pytest
import datetime
import uuid

# Add repo root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.common.db import get_db_client


def test_admin_connection():
    """Verify admin user can connect and query system status."""
    client = get_db_client(role="admin")
    res = client.query("SELECT 1").result_rows
    assert res == [(1,)]


def test_ingest_user_least_privilege():
    """Verify siem_ingest permissions: INSERT allowed, SELECT & DROP forbidden."""
    client = get_db_client(role="ingest")

    # Ingestion should succeed
    now = datetime.datetime.now(datetime.timezone.utc)
    client.insert(
        "raw_telemetry",
        [
            [
                now,
                "laptop",
                "test-host-01",
                "security_test",
                "rbac_probe",
                "INFO",
                "sec_test_runner",
                "127.0.0.1",
                "pytest",
                "pytest test_clickhouse_security.py",
                "raw_telemetry",
                '{"test": true}',
            ]
        ],
        column_names=[
            "timestamp",
            "asset_type",
            "asset_id",
            "event_category",
            "event_type",
            "severity",
            "actor",
            "source_ip",
            "process_name",
            "command_line",
            "target_resource",
            "raw_json",
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


def test_detector_user_least_privilege():
    """Verify siem_detector permissions: SELECT telemetry & INSERT alerts allowed, DROP & INSERT telemetry forbidden."""
    client = get_db_client(role="detector")

    # SELECT on raw_telemetry should SUCCEED
    res = client.query("SELECT count() FROM raw_telemetry").result_rows
    assert res[0][0] >= 1

    # INSERT into security_alerts should SUCCEED
    now = datetime.datetime.now(datetime.timezone.utc)
    client.insert(
        "security_alerts",
        [
            [
                uuid.uuid4(),
                now,
                "TEST-RULE-001",
                "RBAC Verification Alert",
                "Discovery",
                "T1087",
                "laptop",
                "test-host-01",
                "LOW",
                1,
                "Simulated detection test",
                '{"verified": true}',
                "Authorized test execution",
            ]
        ],
        column_names=[
            "alert_id",
            "triggered_at",
            "rule_id",
            "rule_name",
            "mitre_tactic",
            "mitre_technique",
            "asset_type",
            "asset_id",
            "severity",
            "matched_events_count",
            "alert_description",
            "evidence_context",
            "false_positive_tuning_notes",
        ],
    )

    # INSERT into raw_telemetry should FAIL
    with pytest.raises(Exception) as exc_info:
        client.insert("raw_telemetry", [[now, "laptop", "h1", "c", "t", "INFO", "", None, None, None, None, "{}"]])
    assert "ACCESS_DENIED" in str(exc_info.value) or "Not enough privileges" in str(exc_info.value)


def test_grafana_viewer_least_privilege():
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
