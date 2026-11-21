"""
Integration Tests: ClickHouse Data Model & Storage Engine Behavior.
Tests table schemas, data insertion, and ReplacingMergeTree state deduplication.
Requires running ClickHouse instance.
"""

import uuid
import datetime
import pytest
from src.common.db import get_db_client


@pytest.mark.integration
def test_clickhouse_tables_exist():
    """Verify that all core SIEM tables and views exist in database."""
    client = get_db_client(role="admin")
    tables = [row[0] for row in client.query("SHOW TABLES FROM siem").result_rows]
    expected = [
        "raw_telemetry",
        "posture_findings",
        "security_alerts",
        "v_latest_posture",
        "v_posture_summary",
    ]
    for exp in expected:
        assert exp in tables, f"Expected table or view '{exp}' not found in ClickHouse"


@pytest.mark.integration
def test_replacing_merge_tree_deduplication():
    """
    Verify ReplacingMergeTree behavior:
    Inserting an updated scan for the same (asset_type, asset_id, check_id)
    replaces/updates the finding in siem.v_latest_posture.
    """
    admin_client = get_db_client(role="admin")
    ingest_client = get_db_client(role="ingest")

    asset_id = f"test-vm-{uuid.uuid4().hex[:6]}"
    check_id = "CVE-2024-9999"

    # 1. Insert Initial Finding with status 'OPEN'
    t1 = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)
    ingest_client.insert(
        "posture_findings",
        [[
            t1,
            "vm",
            asset_id,
            "trivy",
            "vulnerability",
            check_id,
            "Test Critical Flaw",
            "CRITICAL",
            "OPEN",
            "Patch package",
            "Initial scan result",
        ]],
        column_names=[
            "scan_timestamp", "asset_type", "asset_id", "scanner_tool",
            "finding_type", "check_id", "title", "severity", "status",
            "remediation", "details"
        ],
    )

    # 2. Insert Updated Finding with status 'RESOLVED' and newer timestamp
    t2 = datetime.datetime.now(datetime.timezone.utc)
    ingest_client.insert(
        "posture_findings",
        [[
            t2,
            "vm",
            asset_id,
            "trivy",
            "vulnerability",
            check_id,
            "Test Critical Flaw",
            "CRITICAL",
            "RESOLVED",
            "Patch applied successfully",
            "Remediation scan result",
        ]],
        column_names=[
            "scan_timestamp", "asset_type", "asset_id", "scanner_tool",
            "finding_type", "check_id", "title", "severity", "status",
            "remediation", "details"
        ],
    )

    # 3. Optimize table to trigger merge and query latest view
    admin_client.command("OPTIMIZE TABLE siem.posture_findings FINAL")

    result = admin_client.query(
        f"SELECT status, remediation FROM siem.v_latest_posture WHERE asset_id = '{asset_id}' AND check_id = '{check_id}'"
    ).result_rows

    assert len(result) == 1
    assert result[0][0] == "RESOLVED"
    assert result[0][1] == "Patch applied successfully"
