"""
Correlated Threat Detection Engine for Mini SIEM.
Implements Temporal Sequence Correlation (Improvement 1) using ClickHouse's native windowFunnel().

Security Principles Applied:
  - Temporal Funnel Analytics: Correlates discrete low/medium signals across kill-chain stages into single high-fidelity CRITICAL alerts.
  - False Positive Elimination: Requires strict chronological sequence of actions within tight sliding windows (e.g., 300s, 600s).
  - Least Privilege Access: Operates with siem_detector_role (SELECT telemetry, INSERT/SELECT alerts).
  - Deduplication & Idempotency: Uses fingerprint tracking to prevent alert storming.
"""

import os
import sys
import json
import uuid
import datetime
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file, get_db_client

load_env_file()

CORRELATED_RULES: Dict[str, Dict[str, Any]] = {
    "CORR-VM-001": {
        "rule_id": "CORR-VM-001",
        "rule_name": "Correlated Intrusion: SSH Ingress -> Sudo Escalation -> Credential Dumping",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1078, T1548.003, T1003.008",
        "asset_type": "vm",
        "severity": "CRITICAL",
        "window_seconds": 300,
        "stages": [
            "Stage 1: Remote SSH Authentication (T1078)",
            "Stage 2: Privilege Escalation via Sudo (T1548.003)",
            "Stage 3: Credential Dumping /etc/shadow (T1003.008)",
        ],
        "cond1": "(process_name IN ('sshd', 'sshd-session') OR command_line LIKE '%sshd%' OR command_line LIKE '%USER_LOGIN%' OR event_type = 'ssh_login_success')",
        "cond2": "(process_name = 'sudo' OR command_line LIKE '%/usr/bin/sudo%' OR event_type IN ('sudo_execution', 'sudo_command'))",
        "cond3": "(target_resource = '/etc/shadow' OR command_line LIKE '%/etc/shadow%' OR event_type = 'sensitive_file_access')",
        "alert_description": "Correlated multi-stage host compromise detected: Remote SSH login immediately followed by sudo execution and root /etc/shadow credential harvesting within 5 minutes.",
        "false_positive_tuning_notes": "Temporal windowFunnel(300) requires chronological progression through SSH session, elevated sudo, and shadow file access on the same host asset.",
    },
    "CORR-K8S-001": {
        "rule_id": "CORR-K8S-001",
        "rule_name": "Correlated Cluster Intrusion: Pod Exec -> Secret Harvest -> Privileged Host Escape",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1059, T1552.007, T1611",
        "asset_type": "k8s",
        "severity": "CRITICAL",
        "window_seconds": 600,
        "stages": [
            "Stage 1: Unauthorized Interactive Pod Exec (T1059)",
            "Stage 2: ServiceAccount / Secret Credential Enumeration (T1552.007)",
            "Stage 3: Container Escape via Privileged Pod & Host Root Mount (T1611)",
        ],
        "cond1": "(event_type LIKE '%exec%' OR command_line LIKE '%exec%')",
        "cond2": "(event_type LIKE '%secret%' OR target_resource LIKE '%secret%' OR command_line LIKE '%secret%' OR command_line LIKE '%serviceaccount%')",
        "cond3": "(event_type = 'create_privileged_pod' OR command_line LIKE '%privileged%' OR target_resource LIKE '%escape%')",
        "alert_description": "Correlated multi-stage cluster compromise detected: Unauthorized interactive pod execution followed by ServiceAccount/secret harvesting, culminating in a privileged host-root escape pod deployment within 10 minutes.",
        "false_positive_tuning_notes": "Temporal windowFunnel(600) requires sequential progression from workload breach to credential theft to privileged container creation on the cluster. Suppresses isolated pod exec and routine secret queries.",
    },
}

STATE_FILE = REPO_ROOT / ".correlated_detection_state.json"


def load_state() -> Dict[str, Any]:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_run": None, "fired_alert_keys": {}}


def save_state(state: Dict[str, Any]) -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[!] Warning saving correlated detection state: {e}")


def evaluate_correlated_rules(rule_id_filter: Optional[str] = None, lookback_minutes: int = 60) -> int:
    """Evaluates temporal sequence correlation rules against ClickHouse raw_telemetry."""
    client = get_db_client(role="detector")
    state = load_state()

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    start_dt = now_dt - datetime.timedelta(minutes=lookback_minutes)
    end_dt = now_dt + datetime.timedelta(minutes=5)
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    rules_to_run = (
        {rule_id_filter: CORRELATED_RULES[rule_id_filter]}
        if rule_id_filter and rule_id_filter in CORRELATED_RULES
        else CORRELATED_RULES
    )

    total_alerts_fired = 0
    alerts_to_insert = []

    print("=" * 75)
    print(f"[*] EVALUATING TEMPORAL SEQUENCE CORRELATION RULES ({start_str} to {end_str})")
    print("=" * 75)

    for rule_id, cfg in rules_to_run.items():
        window_sec = cfg["window_seconds"]
        asset_type = cfg["asset_type"]
        c1, c2, c3 = cfg["cond1"], cfg["cond2"], cfg["cond3"]

        funnel_query = f"""
        SELECT
            asset_id,
            windowFunnel({window_sec})(
                toDateTime(timestamp),
                {c1},
                {c2},
                {c3}
            ) AS funnel_stage,
            min(timestamp) AS chain_started,
            max(timestamp) AS chain_ended,
            count() AS total_events
        FROM siem.raw_telemetry
        WHERE asset_type = '{asset_type}'
          AND timestamp >= '{start_str}'
          AND timestamp <= '{end_str}'
        GROUP BY asset_id
        HAVING funnel_stage >= 3
        """

        try:
            matches = client.query(funnel_query).result_rows
            if not matches:
                print(f"[-] Rule {rule_id}: No matching sequence found in window.")
                continue

            for match in matches:
                matched_asset_id = str(match[0])
                stage_reached = int(match[1])
                chain_started = match[2]
                chain_ended = match[3]
                total_events = int(match[4])

                # Deduplication fingerprint based on asset and chain end timestamp
                fingerprint = f"{rule_id}::{matched_asset_id}::{chain_ended.isoformat()}"
                if fingerprint in state.get("fired_alert_keys", {}):
                    print(f"[*] Rule {rule_id}: Skipping already-alerted event window {fingerprint}")
                    continue

                # Fetch detailed forensic evidence sample for this specific chain window
                detail_query = f"""
                SELECT
                    timestamp,
                    actor,
                    process_name,
                    command_line,
                    target_resource,
                    event_type
                FROM siem.raw_telemetry
                WHERE asset_type = '{asset_type}'
                  AND asset_id = '{matched_asset_id}'
                  AND timestamp >= '{chain_started.strftime('%Y-%m-%d %H:%M:%S')}'
                  AND timestamp <= '{chain_ended.strftime('%Y-%m-%d %H:%M:%S')}'
                  AND (
                      ({c1}) OR ({c2}) OR ({c3})
                  )
                ORDER BY timestamp ASC
                LIMIT 20
                """
                detail_rows = client.query(detail_query).result_rows

                # Extract primary actor
                actors = list({str(r[1]) for r in detail_rows if str(r[1]) not in ("unknown", "")})
                primary_actor = actors[0] if actors else "correlated_adversary"

                evidence = {
                    "correlation_engine": "ClickHouse windowFunnel()",
                    "window_seconds": window_sec,
                    "stages_completed": stage_reached,
                    "defined_stages": cfg["stages"],
                    "chain_duration_seconds": max(1, int((chain_ended - chain_started).total_seconds())),
                    "chain_started": chain_started.isoformat(),
                    "chain_ended": chain_ended.isoformat(),
                    "total_matched_events": len(detail_rows),
                    "primary_actor": primary_actor,
                    "all_actors": actors,
                    "chronological_sequence": [
                        {
                            "timestamp": str(r[0]),
                            "actor": r[1],
                            "process": r[2],
                            "cmd": (r[3] or "")[:200],
                            "target": r[4],
                            "event_type": r[5],
                        }
                        for r in detail_rows
                    ],
                }

                alert_id = uuid.uuid4()
                triggered_at = now_dt

                alerts_to_insert.append([
                    alert_id,
                    triggered_at,
                    cfg["rule_id"],
                    cfg["rule_name"],
                    cfg["mitre_tactic"],
                    cfg["mitre_technique"],
                    cfg["asset_type"],
                    matched_asset_id,
                    cfg["severity"],
                    len(detail_rows),
                    cfg["alert_description"],
                    json.dumps(evidence),
                    cfg["false_positive_tuning_notes"],
                ])

                state.setdefault("fired_alert_keys", {})[fingerprint] = now_dt.isoformat()
                total_alerts_fired += 1

                print("\n" + "#" * 75)
                print(f"[!] CORRELATED SECURITY ALERT FIRED: [{cfg['severity']}] {cfg['rule_id']}")
                print(f"    Name:       {cfg['rule_name']}")
                print(f"    Asset:      {cfg['asset_type']} / {matched_asset_id}")
                print(f"    Actor:      {primary_actor}")
                print(f"    MITRE:      {cfg['mitre_technique']} ({cfg['mitre_tactic']})")
                print(f"    Stages:     3/3 Completed in {evidence['chain_duration_seconds']}s")
                print(f"    Timeline:   {chain_started} -> {chain_ended}")
                print("#" * 75)

        except Exception as e:
            print(f"[-] Error evaluating correlated rule '{rule_id}': {e}")

    if alerts_to_insert:
        try:
            client.insert(
                "security_alerts",
                alerts_to_insert,
                column_names=[
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
                ],
            )
            print(f"\n[+] Successfully saved {len(alerts_to_insert)} correlated alert(s) to siem.security_alerts.")
        except Exception as e:
            print(f"[-] Error saving correlated alerts to ClickHouse: {e}")

    state["last_run"] = now_dt.isoformat()
    save_state(state)
    return total_alerts_fired


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM Correlated Detection Engine")
    parser.add_argument("--rule", type=str, default=None, help="Specific correlated rule ID to evaluate (e.g. CORR-VM-001)")
    parser.add_argument("--once", action="store_true", help="Execute single detection evaluation and exit")
    parser.add_argument("--lookback", type=int, default=60, help="Lookback window in minutes (default: 60)")
    args = parser.parse_args()

    fired = evaluate_correlated_rules(rule_id_filter=args.rule, lookback_minutes=args.lookback)
    print(f"\n[*] Correlated evaluation complete. Fired {fired} new alert(s).")


if __name__ == "__main__":
    main()
