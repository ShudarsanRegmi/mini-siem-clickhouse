"""
Detection Rule: SEC-K8S-002
Name: Execution & Discovery: Interactive Container Exec & Credential Snooping
MITRE ATT&CK: T1059 (Execution), T1552.007 (Container Credentials) / Tactic: Execution / Credential Access
Target Asset: k8s
Severity: HIGH

False Positive Tuning & Baseline Exceptions:
  - Allowed: Automated kubelet / kube-proxy liveness/readiness probes (actor like system:node:%).
  - Allowed: Pre-approved CI/CD deployment service accounts.
  - Trigger: Interactive kubectl exec commands by user identities (e.g. kubernetes-admin, developers) targeting workloads to inspect tokens or execute shells.
"""

from typing import Dict, Any

RULE_CONFIG: Dict[str, Any] = {
    "rule_id": "SEC-K8S-002",
    "rule_name": "Execution & Discovery: Interactive Container Exec & Credential Snooping",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1552.007",
    "asset_type": "k8s",
    "severity": "HIGH",
    "alert_description": "Detected interactive exec request into running Kubernetes pod, potentially indicating interactive shell access or token enumeration.",
    "false_positive_tuning_notes": "Suppressed internal node health check probes (system:node:%). Alerted on interactive user sessions (kubernetes-admin) in production/default namespaces.",
}


def build_query(start_time: str, end_time: str) -> str:
    """Returns ClickHouse SQL query for detecting interactive pod execs."""
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
          event_type LIKE '%exec%'
          OR command_line LIKE '%exec%'
          OR target_resource LIKE '%victim-target-app%'
      )
      -- False Positive Tuning: Exclude node internal kubelet probes
      AND actor NOT LIKE 'system:node:%'
      AND actor NOT LIKE 'system:serviceaccount:kube-system:%'
    ORDER BY timestamp ASC;
    """
