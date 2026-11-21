"""
Detection Rule: SEC-VM-001
Name: Credential Access: Unauthorized /etc/shadow Access
MITRE ATT&CK: T1003 (OS Credential Dumping) / Tactic: Credential Access
Target Asset: vm
Severity: CRITICAL

False Positive Tuning & Baseline Exceptions:
  - Allowed: Legitimate PAM/authentication binaries (login, sshd, passwd, chpasswd, useradd, unix_chkpwd).
  - Allowed: Routine systemd user accounting daemon (systemd-userwork).
  - Trigger: Interactive user commands, scripts, or unexpected processes (cat, awk, python, curl, sudo /bin/cat) reading /etc/shadow.
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-VM-001",
    "rule_name": "Credential Access: Unauthorized /etc/shadow Access",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1003",
    "asset_type": "vm",
    "severity": "CRITICAL",
    "alert_description": "Detected suspicious read or access attempt on /etc/shadow, indicating potential OS credential dumping or privilege escalation.",
    "false_positive_tuning_notes": "Suppressed standard authentication daemons (login, sshd, passwd, systemd-userwork). Flagged interactive shell and CLI dumping utilities.",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting /etc/shadow credential dumping."""
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
          target_resource = '/etc/shadow'
          OR command_line LIKE '%/etc/shadow%'
          OR event_type = 'sensitive_file_access'
      )
      -- False Positive Tuning: Exclude standard system authentication daemons
      AND process_name NOT IN ('login', 'sshd', 'passwd', 'useradd', 'chpasswd', 'cron', 'systemd-userwork')
      -- Flag non-PAM interactive dumps
      AND (
          command_line LIKE '%cat%'
          OR command_line LIKE '%shadow%'
          OR actor != 'root'
          OR event_type = 'sensitive_file_access'
      )
    ORDER BY timestamp ASC;
    """
