"""
Integration Test: 5 Realistic Attack Scenarios & Telemetry Generation.
Validates that:
  1. Attack 1 (VM Credential Access): Generates sensitive file access telemetry in ClickHouse.
  2. Attack 2 (VM Cron Persistence): Generates cron modification telemetry in ClickHouse.
  3. Attack 3 (K8s Privileged Pod): Generates create_privileged_pod telemetry in ClickHouse.
  4. Attack 4 (K8s Interactive Exec): Generates pod exec telemetry in ClickHouse.
  5. Attack 5 (GitHub Secret Leak): Generates authenticated webhook push events in ClickHouse.
"""

import pytest
from src.common.db import get_db_client


@pytest.mark.integration
def test_all_five_attack_telemetry_types_exist():
    """Queries ClickHouse to verify that events from all 5 attack scenarios are captured."""
    client = get_db_client(role="viewer")

    # Scenario 1: VM Sensitive file access (/etc/shadow)
    s1 = client.query("""
        SELECT count() FROM siem.raw_telemetry
        WHERE asset_type = 'vm' AND target_resource = '/etc/shadow';
    """).result_rows[0][0]
    assert s1 > 0, "Scenario 1: No /etc/shadow access events found in ClickHouse"

    # Scenario 2: VM Cron Persistence (/etc/cron.d)
    s2 = client.query("""
        SELECT count() FROM siem.raw_telemetry
        WHERE asset_type = 'vm' AND target_resource = '/etc/cron.d';
    """).result_rows[0][0]
    assert s2 > 0, "Scenario 2: No /etc/cron.d modification events found in ClickHouse"

    # Scenario 3: Kubernetes Privileged Pod
    s3 = client.query("""
        SELECT count() FROM siem.raw_telemetry
        WHERE asset_type = 'k8s' AND event_type = 'create_privileged_pod';
    """).result_rows[0][0]
    assert s3 > 0, "Scenario 3: No create_privileged_pod events found in ClickHouse"

    # Scenario 4: Kubernetes Pod Exec
    s4 = client.query("""
        SELECT count() FROM siem.raw_telemetry
        WHERE asset_type = 'k8s' AND event_type LIKE '%exec%';
    """).result_rows[0][0]
    assert s4 > 0, "Scenario 4: No pod exec audit events found in ClickHouse"

    # Scenario 5: GitHub Secret Leak Commit Webhook
    s5 = client.query("""
        SELECT count() FROM siem.raw_telemetry
        WHERE asset_type = 'github' AND actor = 'negligent_developer';
    """).result_rows[0][0]
    assert s5 > 0, "Scenario 5: No git secret leak webhook events found in ClickHouse"
