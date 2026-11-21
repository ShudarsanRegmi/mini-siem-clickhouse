"""
Master Attack Simulation Orchestrator.
Executes 5 realistic cyber attack scenarios across Linux VM, Kubernetes, and GitHub:
  1. VM Credential Dumping (/etc/shadow access - T1003)
  2. VM Persistence & Reverse Shell (/etc/cron.d/ backdoor - T1053.003, T1059.004)
  3. Kubernetes Privileged Pod & Host Root Mount (T1610, T1611)
  4. Kubernetes Pod Interactive Exec & ServiceAccount Token Theft (T1059, T1552.007)
  5. GitHub Secret Leakage in Commit (T1552.001)

Automatically flushes/synchronizes telemetry from debianvm and K8s into ClickHouse.
"""

import os
import sys
import subprocess
import argparse
import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file, get_db_client

load_env_file()


def run_scenario_1():
    print("\n" + "="*70)
    print(">>> RUNNING ATTACK SCENARIO 1: VM CREDENTIAL DUMPING (T1003)")
    print("="*70)
    cmd = [str(REPO_ROOT / "attacks" / "attack_1_cred_dump.sh"), "debianvm"]
    subprocess.check_call(cmd)


def run_scenario_2():
    print("\n" + "="*70)
    print(">>> RUNNING ATTACK SCENARIO 2: VM PERSISTENCE & REVERSE SHELL (T1053/T1059)")
    print("="*70)
    cmd = [str(REPO_ROOT / "attacks" / "attack_2_reverse_shell.sh"), "debianvm"]
    subprocess.check_call(cmd)


def run_scenario_3():
    print("\n" + "="*70)
    print(">>> RUNNING ATTACK SCENARIO 3: K8S PRIVILEGED POD ESCAPE (T1610/T1611)")
    print("="*70)
    cmd = [str(REPO_ROOT / "attacks" / "attack_3_privileged_pod.sh")]
    subprocess.check_call(cmd)


def run_scenario_4():
    print("\n" + "="*70)
    print(">>> RUNNING ATTACK SCENARIO 4: K8S INTERACTIVE EXEC & TOKEN HARVEST (T1059/T1552)")
    print("="*70)
    cmd = [str(REPO_ROOT / "attacks" / "attack_4_k8s_exec.sh")]
    subprocess.check_call(cmd)


def run_scenario_5():
    print("\n" + "="*70)
    print(">>> RUNNING ATTACK SCENARIO 5: GITHUB COMMITTED SECRET LEAK (T1552.001)")
    print("="*70)
    cmd = [sys.executable, str(REPO_ROOT / "attacks" / "attack_5_git_secret_leak.py")]
    subprocess.check_call(cmd)


def sync_telemetry():
    """Flushes newly generated telemetry from debianvm and K8s into ClickHouse."""
    print("\n[*] Synchronizing attack telemetry from VM and K8s into ClickHouse...")

    # 1. Sync VM Telemetry via collector
    try:
        vm_collector_cmd = [
            sys.executable,
            str(REPO_ROOT / "assets" / "vm" / "collector.py"),
            "--ssh-host", "172.16.151.134",
            "--ssh-user", "aparichit",
        ]
        subprocess.check_call(vm_collector_cmd)
    except Exception as e:
        print(f"[!] Warning syncing VM telemetry: {e}")

    # 2. Sync K8s Audit Telemetry
    try:
        k8s_collector_cmd = [
            sys.executable,
            str(REPO_ROOT / "assets" / "k8s" / "collector.py"),
        ]
        subprocess.check_call(k8s_collector_cmd)
    except Exception as e:
        print(f"[!] Warning syncing K8s telemetry: {e}")


def display_attack_telemetry_summary():
    """Queries ClickHouse for latest attack-related telemetry events."""
    try:
        client = get_db_client(role="viewer")
        print("\n" + "="*70)
        print("          CLICKHOUSE RAW TELEMETRY BY ASSET CLASS")
        print("="*70)
        counts = client.query("""
            SELECT asset_type, count(), max(timestamp)
            FROM siem.raw_telemetry
            GROUP BY asset_type
            ORDER BY asset_type;
        """).result_rows
        print(f"{'Asset Type':<15} | {'Event Count':<15} | {'Latest Event Timestamp'}")
        print("-" * 70)
        for r in counts:
            print(f"{r[0]:<15} | {r[1]:<15} | {r[2]}")
        print("="*70 + "\n")

        print("="*70)
        print("          CLICKHOUSE SECURITY ALERTS (DETECTION SUMMARY)")
        print("="*70)
        alert_rows = client.query("""
            SELECT triggered_at, severity, asset_type, rule_name, matched_events_count
            FROM siem.security_alerts
            ORDER BY triggered_at DESC
            LIMIT 5;
        """).result_rows
        print(f"{'Triggered At':<23} | {'Severity':<8} | {'Asset':<6} | {'Rule Name':<30} | {'Count'}")
        print("-" * 75)
        for ar in alert_rows:
            print(f"{str(ar[0])[:22]:<23} | {ar[1]:<8} | {ar[2]:<6} | {ar[3][:30]:<30} | {ar[4]}")
        print("="*75 + "\n")
    except Exception as e:
        print(f"[!] Note: Could not query ClickHouse: {e}")


def main():
    parser = argparse.ArgumentParser(description="Master Attack Simulation Orchestrator")
    parser.add_argument(
        "--scenario",
        choices=["1", "2", "3", "4", "5", "all"],
        default="all",
        help="Attack scenario to execute (default: all)",
    )
    args = parser.parse_args()

    scenarios = {
        "1": run_scenario_1,
        "2": run_scenario_2,
        "3": run_scenario_3,
        "4": run_scenario_4,
        "5": run_scenario_5,
    }

    if args.scenario == "all":
        for num in ("1", "2", "3", "4", "5"):
            scenarios[num]()
    else:
        scenarios[args.scenario]()

    # Sync logs generated by attacks into ClickHouse
    sync_telemetry()

    # Trigger Detection Engine to analyze newly ingested attack telemetry
    try:
        from detections.engine import evaluate_rules
        print("\n[*] Triggering Detection Engine evaluation...")
        fired = evaluate_rules(lookback_minutes=60)
        print(f"[+] Detection Engine evaluated all rules and fired {fired} new alert(s).")
    except Exception as e:
        print(f"[!] Warning evaluating detection rules: {e}")

    display_attack_telemetry_summary()


if __name__ == "__main__":
    main()
