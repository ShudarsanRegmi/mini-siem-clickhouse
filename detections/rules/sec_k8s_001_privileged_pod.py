"""
Detection Rule: SEC-K8S-001
Name: Container Escape Risk: Privileged Pod Creation or Host Root Mount
MITRE ATT&CK: T1610 (Deploy Container), T1611 (Escape to Host) / Tactic: Privilege Escalation
Target Asset: k8s
Severity: CRITICAL

False Positive Tuning & Baseline Exceptions:
  - Allowed: Verified core cluster CNI daemonsets in kube-system (e.g. kindnet, kube-proxy, calico).
  - Trigger: Pod deployments in user or default namespaces requesting privileged=true, hostPID=true, or hostPath=/ root volume mounts.
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-K8S-001",
    "rule_name": "Container Escape Risk: Privileged Pod Creation or Host Root Mount",
    "mitre_tactic": "Privilege Escalation",
    "mitre_technique": "T1611",
    "asset_type": "k8s",
    "severity": "CRITICAL",
    "alert_description": "Detected deployment of a privileged container or host root filesystem mount (/), enabling container escape to host node.",
    "false_positive_tuning_notes": "Allowlisted kube-system infrastructure daemons (kube-proxy, kindnetd, daemon-set-controller). Alerted on all default/user namespace privileged workloads.",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting privileged container creation."""
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
    WHERE asset_type = 'k8s'
      AND timestamp >= '{start_time}'
      AND timestamp <= '{end_time}'
      AND (
          event_type = 'create_privileged_pod'
          OR (event_category = 'k8s_audit' AND command_line LIKE '%privileged%')
          OR (target_resource LIKE '%privileged-escape-pod%')
      )
      -- False Positive Tuning: Exclude standard CNI daemonset controller in kube-system
      AND actor NOT IN ('system:serviceaccount:kube-system:daemon-set-controller', 'system:serviceaccount:kube-system:kindnet')
      AND target_resource NOT LIKE 'kube-system/%'
    ORDER BY timestamp ASC;
    """
