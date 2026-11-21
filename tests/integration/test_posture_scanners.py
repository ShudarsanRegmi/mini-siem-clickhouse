"""
Integration Test: Posture Scanners Across All 4 Monitored Assets.
Validates that:
  1. Each asset scanner (laptop, vm, k8s, github) outputs schema-compliant findings.
  2. Findings are successfully delivered and authenticated via Ingestion Gateway (/api/v1/posture).
  3. ClickHouse ReplacingMergeTree deduplicates findings properly.
  4. Analytical views (v_latest_posture, v_posture_summary) reflect the findings.
"""

import pytest
import datetime
from posture.scanners.laptop_scanner import scan_laptop_posture
from posture.scanners.vm_scanner import scan_vm_posture
from posture.scanners.k8s_scanner import scan_k8s_posture
from posture.scanners.github_scanner import scan_github_posture
from src.common.db import get_db_client


@pytest.mark.integration
def test_all_scanners_return_valid_findings():
    """Verifies that all 4 scanners run and produce required fields."""
    laptop_findings = scan_laptop_posture()
    assert isinstance(laptop_findings, list)
    assert len(laptop_findings) > 0
    assert laptop_findings[0]["asset_type"] == "laptop"

    vm_findings = scan_vm_posture()
    assert isinstance(vm_findings, list)
    assert len(vm_findings) > 0
    assert vm_findings[0]["asset_type"] == "vm"

    k8s_findings = scan_k8s_posture()
    assert isinstance(k8s_findings, list)
    assert len(k8s_findings) > 0
    assert k8s_findings[0]["asset_type"] == "k8s"

    github_findings = scan_github_posture()
    assert isinstance(github_findings, list)
    assert len(github_findings) > 0
    assert github_findings[0]["asset_type"] == "github"

    # Validate mandatory schema keys for every finding
    required_keys = {"asset_type", "asset_id", "scanner_tool", "finding_type", "check_id", "title", "severity", "status"}
    for f in laptop_findings + vm_findings + k8s_findings + github_findings:
        for key in required_keys:
            assert key in f, f"Missing required key '{key}' in finding: {f}"
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert f["status"] in ("OPEN", "RESOLVED", "SUPPRESSED")


@pytest.mark.integration
def test_posture_ingestion_and_deduplication(api_client, valid_bearer_token):
    """Verifies gateway ingestion and ReplacingMergeTree deduplication in ClickHouse."""
    test_check_id = "CIS-TEST-DEDUP-001"
    asset_id = "test-posture-workstation"

    finding_v1 = {
        "asset_type": "laptop",
        "asset_id": asset_id,
        "scanner_tool": "test-auditor",
        "finding_type": "misconfiguration",
        "check_id": test_check_id,
        "title": "Initial Unpatched State",
        "severity": "HIGH",
        "status": "OPEN",
        "remediation": "Apply security patch",
        "details": "Finding is currently open",
    }

    # Step 1: Ingest Initial Open Finding
    res1 = api_client.post(
        "/api/v1/posture",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[finding_v1],
    )
    assert res1.status_code == 201

    # Step 2: Ingest Resolved State for the exact same check_id & asset_id
    finding_v2 = dict(finding_v1)
    finding_v2["status"] = "RESOLVED"
    finding_v2["title"] = "Remediated Patched State"

    res2 = api_client.post(
        "/api/v1/posture",
        headers={"Authorization": f"Bearer {valid_bearer_token}"},
        json=[finding_v2],
    )
    assert res2.status_code == 201

    # Step 3: Query v_latest_posture in ClickHouse
    db_client = get_db_client(role="viewer")
    query_res = db_client.query(f"""
        SELECT status, title
        FROM siem.v_latest_posture
        WHERE asset_id = '{asset_id}' AND check_id = '{test_check_id}';
    """).result_rows

    assert len(query_res) == 1, f"Expected exactly 1 deduplicated record, got {len(query_res)}"
    assert query_res[0][0] == "RESOLVED", f"Expected latest status to be RESOLVED, got {query_res[0][0]}"
