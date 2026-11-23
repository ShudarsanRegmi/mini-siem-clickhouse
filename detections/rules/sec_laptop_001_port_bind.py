"""
Detection Rule: SEC-LAPTOP-001
Name: Defense Evasion & C2: Unauthorized External Port Binding or Backdoor Listener
MITRE ATT&CK: T1571 (Non-Standard Port), T1049 (System Network Connections Discovery)
Target Asset: laptop
Severity: HIGH

False Positive Tuning & Baseline Exceptions:
  - Allowed: Verified local Docker bridge proxies and loopback bindings (127.0.0.1, ::1).
  - Trigger: Processes spawning listeners on 0.0.0.0 or [::] utilizing netcat, python http servers, or unauthorized shell listeners.
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-LAPTOP-001",
    "rule_name": "Defense Evasion & C2: Unauthorized External Port Binding or Backdoor Listener",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "T1571",
    "asset_type": "laptop",
    "severity": "HIGH",
    "alert_description": "Detected a process binding an unauthorized listening socket on public network interface (0.0.0.0), potentially establishing an inbound backdoor or rogue server.",
    "false_positive_tuning_notes": "Suppressed verified loopback developer proxies (127.0.0.1). Flagged non-standard CLI listener utilities (nc, ncat, python -m http.server, socat).",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting unauthorized listening port bindings on laptop."""
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
    WHERE asset_type = 'laptop'
      AND timestamp >= '{start_time}'
      AND timestamp <= '{end_time}'
      AND (
          event_type IN ('listening_port', 'port_listen', 'socket_bind', 'unauthorized_listener')
          OR (
              process_name IN ('nc', 'netcat', 'ncat', 'socat')
              AND (command_line LIKE '%-l%' OR command_line LIKE '%-p%')
          )
          OR (
              process_name IN ('python', 'python3')
              AND command_line LIKE '%http.server%'
          )
          OR (
              event_category = 'network'
              AND (target_resource LIKE 'port/%' OR target_resource LIKE 'listen:%')
              AND (source_ip = '0.0.0.0' OR source_ip = '::' OR source_ip IS NULL)
          )
      )
      -- False Positive Tuning: Exclude standard loopback local addresses
      AND target_resource NOT LIKE '%127.0.0.1%'
    ORDER BY timestamp ASC;
    """
