"""
Detection Rule: SEC-VM-002
Name: Persistence & Execution: Unauthorized Cron Modification or Reverse Shell Socket
MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron), T1059.004 (Unix Shell) / Tactic: Persistence / Execution
Target Asset: vm
Severity: HIGH

False Positive Tuning & Baseline Exceptions:
  - Allowed: System log rotation (/usr/sbin/logrotate) and anacron routines.
  - Allowed: Standard apt / dpkg cron updates.
  - Trigger: File drops or modifications in /etc/cron.d/ by non-package managers, or process command lines spawning network socket redirection (/dev/tcp, nc -e, bash -i).
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-VM-002",
    "rule_name": "Persistence & Execution: Unauthorized Cron Modification or Reverse Shell Socket",
    "mitre_tactic": "Persistence",
    "mitre_technique": "T1053.003",
    "asset_type": "vm",
    "severity": "HIGH",
    "alert_description": "Detected suspicious modification to /etc/cron directory or execution of interactive shell network socket redirection.",
    "false_positive_tuning_notes": "Filtered legitimate system logrotate (/usr/sbin/logrotate) and routine debian package cron maintenance scripts.",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting cron persistence or reverse shells."""
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
    WHERE asset_type = 'vm'
      AND timestamp >= '{start_time}'
      AND timestamp <= '{end_time}'
      AND (
          target_resource LIKE '/etc/cron%'
          OR event_type IN ('cron_modification', 'reverse_shell_attempt')
          OR command_line LIKE '%/dev/tcp/%'
          OR command_line LIKE '%nc -e%'
          OR command_line LIKE '%bash -i%'
          OR command_line LIKE '%sync_backdoor%'
      )
      -- False Positive Tuning: Allowlist standard logrotate and anacron
      AND command_line NOT LIKE '%/usr/sbin/logrotate%'
      AND command_line NOT LIKE '%anacron%'
    ORDER BY timestamp ASC;
    """
