"""
Integration tests for Temporal Sequence Correlation Engine (CORR-VM-001 & CORR-K8S-001).
Validates ClickHouse native windowFunnel() execution, rule evaluation, and alert serialization.
"""

import pytest
import datetime
from pathlib import Path
import json

from src.common.db import get_db_client, load_env_file
from detections.run_correlated_detections import CORRELATED_RULES, evaluate_correlated_rules

load_env_file()


def test_correlated_rules_definitions():
    """Validates that all correlated rules have required metadata, query predicates, and windows."""
    assert "CORR-VM-001" in CORRELATED_RULES
    assert "CORR-K8S-001" in CORRELATED_RULES

    for rule_id, cfg in CORRELATED_RULES.items():
        assert cfg["rule_id"] == rule_id
        assert cfg["severity"] == "CRITICAL"
        assert cfg["window_seconds"] > 0
        assert len(cfg["stages"]) == 3
        assert "cond1" in cfg and "cond2" in cfg and "cond3" in cfg
        assert cfg["asset_type"] in ("vm", "k8s")


def test_clickhouse_window_funnel_syntax():
    """Executes the raw windowFunnel() SQL against ClickHouse to verify query compilation."""
    client = get_db_client(role="detector")

    for rule_id, cfg in CORRELATED_RULES.items():
        w = cfg["window_seconds"]
        c1, c2, c3 = cfg["cond1"], cfg["cond2"], cfg["cond3"]
        asset_type = cfg["asset_type"]

        query = f"""
        SELECT
            asset_id,
            windowFunnel({w})(
                toDateTime(timestamp),
                {c1},
                {c2},
                {c3}
            ) AS funnel_stage,
            count() AS total_events
        FROM siem.raw_telemetry
        WHERE asset_type = '{asset_type}'
          AND timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY asset_id
        """

        result = client.query(query)
        assert result is not None
        assert isinstance(result.result_rows, list)


def test_evaluate_correlated_engine_execution():
    """Runs a single evaluation pass of the correlated engine without raising exceptions."""
    fired = evaluate_correlated_rules(lookback_minutes=60)
    assert isinstance(fired, int)
    assert fired >= 0


def test_security_alerts_table_has_required_schema():
    """Confirms that siem.security_alerts contains all expected fields for correlated detections."""
    client = get_db_client(role="detector")
    cols = [row[0] for row in client.query("DESCRIBE TABLE siem.security_alerts").result_rows]

    expected = [
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
    ]
    for col in expected:
        assert col in cols
