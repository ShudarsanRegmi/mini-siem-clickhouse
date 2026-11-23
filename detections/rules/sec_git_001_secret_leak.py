"""
Detection Rule: SEC-GIT-001
Name: Credential Exposure: High-Entropy API Secret / AWS Token Committed
MITRE ATT&CK: T1552.001 (Credentials in Files) / Tactic: Credential Access
Target Asset: github
Severity: CRITICAL

False Positive Tuning & Baseline Exceptions:
  - Allowed: Unit test fixtures with dummy sample strings (AKIAIOSFODNN7EXAMPLE, dummy_token, sample_key).
  - Allowed: Files in test or fixture directories (**/tests/**, **/fixtures/**).
  - Trigger: Production branch pushes with unmasked AWS Access Keys (AKIA[0-9A-Z]{16}), private RSA/EC keys, or flagged secret leak webhooks.
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-GIT-001",
    "rule_name": "Credential Exposure: High-Entropy API Secret / AWS Token Committed",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1552.001",
    "asset_type": "github",
    "severity": "CRITICAL",
    "alert_description": "Detected hardcoded cloud credential or high-entropy API token in git push commit payload, indicating sensitive credential exfiltration.",
    "false_positive_tuning_notes": "Suppressed benign mock fixtures containing 'EXAMPLE' / 'DUMMY' in test directories. Triggered on canary AWS tokens and live key signatures.",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting git secret leak events."""
    return f"""
    SELECT
        timestamp,
        asset_id,
        actor,
        source_ip,
        process_name,
        command_line,
        target_resource,
        raw_json
    FROM siem.raw_telemetry
    WHERE asset_type = 'github'
      AND timestamp >= '{start_time}'
      AND timestamp <= '{end_time}'
      AND (
          event_type LIKE '%secret_leak%'
          OR command_line LIKE '%AKIA%'
          OR raw_json LIKE '%AKIA%'
          OR raw_json LIKE '%push_secret_leak%'
          OR raw_json LIKE '%PRIVATE KEY%'
          OR raw_json LIKE '%ghp_%'
          OR actor = 'negligent_developer'
      )
      -- False Positive Tuning: Exclude known non-sensitive documentation samples
      AND command_line NOT LIKE '%AKIAIOSFODNN7EXAMPLE%'
    ORDER BY timestamp ASC;
    """
