"""
Mini SIEM Threat Detection Engine.
Security Principles Applied:
  - Least Privilege: Connects strictly using 'siem_detector_role' (SELECT telemetry, INSERT/SELECT alerts).
  - Idempotency & Deduplication: Prevents alert storming by tracking event windows and fingerprinting matches.
  - Fail-Secure & Resilient: Graceful exception handling; continuous operation even during transient network disconnects.
  - Forensic Context: Attaches evidence context, actor attribution, and MITRE ATT&CK mapping to each alert.
"""

import os
import sys
import time
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
from detections.rules.sec_vm_001_cred_dump import RULE_CONFIG as CONFIG_VM_001, build_query as QUERY_VM_001
from detections.rules.sec_vm_002_cron_persistence import RULE_CONFIG as CONFIG_VM_002, build_query as QUERY_VM_002
from detections.rules.sec_k8s_001_privileged_pod import RULE_CONFIG as CONFIG_K8S_001, build_query as QUERY_K8S_001
from detections.rules.sec_k8s_002_suspicious_exec import RULE_CONFIG as CONFIG_K8S_002, build_query as QUERY_K8S_002
from detections.rules.sec_k8s_003_vulnerable_workload_exploit import RULE_CONFIG as CONFIG_K8S_003, build_query as QUERY_K8S_003
from detections.rules.sec_laptop_001_port_bind import RULE_CONFIG as CONFIG_LAPTOP_001, build_query as QUERY_LAPTOP_001
from detections.rules.sec_git_001_secret_leak import RULE_CONFIG as CONFIG_GIT_001, build_query as QUERY_GIT_001

load_env_file()

RULES = [
    {"config": CONFIG_VM_001, "query_builder": QUERY_VM_001},
    {"config": CONFIG_VM_002, "query_builder": QUERY_VM_002},
    {"config": CONFIG_K8S_001, "query_builder": QUERY_K8S_001},
    {"config": CONFIG_K8S_002, "query_builder": QUERY_K8S_002},
    {"config": CONFIG_K8S_003, "query_builder": QUERY_K8S_003},
    {"config": CONFIG_LAPTOP_001, "query_builder": QUERY_LAPTOP_001},
    {"config": CONFIG_GIT_001, "query_builder": QUERY_GIT_001},
]

STATE_FILE = REPO_ROOT / ".detection_state.json"


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
        print(f"[!] Warning saving detection state: {e}")


def evaluate_rules(lookback_minutes: int = 60) -> int:
    """Evaluates all detection rules against raw_telemetry in ClickHouse."""
    client = get_db_client(role="detector")
    state = load_state()

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    start_dt = now_dt - datetime.timedelta(minutes=lookback_minutes)

    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    total_alerts_fired = 0
    alerts_to_insert = []

    for rule_entry in RULES:
        cfg = rule_entry["config"]
        query_fn = rule_entry["query_builder"]
        query = query_fn(start_str, end_str)

        try:
            matched_events = client.query(query).result_rows
            if not matched_events:
                continue

            # Group matched events by (asset_id, actor) to prevent 1-alert-per-row flooding
            grouped: Dict[str, List[Any]] = {}
            for row in matched_events:
                # row: [timestamp, asset_id, actor, source_ip, process_name, command_line, target_resource, raw_json]
                asset_id = str(row[1])
                actor = str(row[2])
                group_key = f"{cfg['rule_id']}::{asset_id}::{actor}"
                grouped.setdefault(group_key, []).append(row)

            for group_key, events in grouped.items():
                # Fingerprint check: avoid re-alerting on the identical event timestamp set
                latest_ts = str(events[-1][0])
                alert_fingerprint = f"{group_key}::{latest_ts}"
                if alert_fingerprint in state.get("fired_alert_keys", {}):
                    continue

                # Prepare Forensic Evidence Context
                evidence = {
                    "matched_count": len(events),
                    "rule_id": cfg["rule_id"],
                    "actor": events[0][2],
                    "target_resource": events[0][6],
                    "sample_command": events[0][5],
                    "events_sample": [
                        {
                            "time": str(e[0]),
                            "process": e[4],
                            "cmd": (e[5] or "")[:200],
                            "target": e[6],
                        }
                        for e in events[:5]
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
                    events[0][1],  # asset_id
                    cfg["severity"],
                    len(events),
                    cfg["alert_description"],
                    json.dumps(evidence),
                    cfg["false_positive_tuning_notes"],
                ])

                state.setdefault("fired_alert_keys", {})[alert_fingerprint] = now_dt.isoformat()
                total_alerts_fired += 1

                print(f"[!] ALERT FIRED: [{cfg['severity']}] {cfg['rule_name']}")
                print(f"    Asset: {cfg['asset_type']} ({events[0][1]}) | Actor: {events[0][2]}")
                print(f"    Matched: {len(events)} events | Technique: {cfg['mitre_technique']}")

        except Exception as e:
            print(f"[-] Error evaluating rule '{cfg['rule_id']}': {e}")

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
            print(f"[+] Successfully recorded {len(alerts_to_insert)} security alert(s) in ClickHouse.")
        except Exception as e:
            print(f"[-] Error recording alerts: {e}")

    state["last_run"] = now_dt.isoformat()
    save_state(state)
    return total_alerts_fired


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM Detection Engine")
    parser.add_argument("--once", action="store_true", help="Execute single detection cycle and exit")
    parser.add_argument("--daemon", action="store_true", help="Run detection engine continuously as a daemon")
    parser.add_argument("--interval", type=int, default=10, help="Scan interval in seconds (default: 10s)")
    parser.add_argument("--lookback", type=int, default=60, help="Lookback window in minutes (default: 60m)")
    args = parser.parse_args()

    print("=" * 70)
    print("      MINI SIEM DETECTION ENGINE (CLICKHOUSE ANALYTICS)")
    print("=" * 70)
    print(f"[*] Loaded {len(RULES)} active detection rules.")
    print(f"[*] Evaluation window: last {args.lookback} minute(s).")

    if args.once or not args.daemon:
        fired = evaluate_rules(lookback_minutes=args.lookback)
        print(f"[*] Detection cycle completed. Fired {fired} new alert(s).")
    else:
        print(f"[*] Starting daemon loop (evaluating every {args.interval}s)... Press Ctrl+C to stop.")
        try:
            while True:
                evaluate_rules(lookback_minutes=args.lookback)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Stopping Detection Engine daemon.")


if __name__ == "__main__":
    main()
