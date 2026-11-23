#!/usr/bin/env python3
"""
Master Orchestrator for Correlated Attack Simulations & Temporal Sequence Detections.
Demonstrates Improvement 1 (Log Correlation via windowFunnel) against Linux VM and Kubernetes.

Scenarios:
  1. Linux Host Compromise Kill Chain (CORR-VM-001):
     SSH Auth -> Sudo Escalation -> /etc/shadow Credential Dumping (300s window)
  2. Kubernetes Cluster Compromise Kill Chain (CORR-K8S-001):
     Interactive Pod Exec -> ServiceAccount Token Snooping -> Privileged Host Escape (600s window)
"""

import os
import sys
import time
import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file, get_db_client

load_env_file()

CORR_DIR = REPO_ROOT / "attacks" / "correlated"
VM_SCRIPT = CORR_DIR / "attack_corr_vm_killchain.sh"
K8S_SCRIPT = CORR_DIR / "attack_corr_k8s_killchain.sh"


def run_cmd(cmd_list: list, title: str) -> bool:
    print("\n" + "=" * 78)
    print(f"[*] RUNNING: {title}")
    print(f"[*] Command: {' '.join(str(c) for c in cmd_list)}")
    print("=" * 78)
    start_time = time.time()
    try:
        proc = subprocess.run(cmd_list, check=True, text=True)
        duration = time.time() - start_time
        print(f"\n[+] {title} completed successfully in {duration:.2f}s.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[-] {title} failed with exit code {e.returncode}.")
        return False


def display_recent_correlated_alerts():
    """Queries ClickHouse for the latest correlated security alerts and displays them formatted."""
    try:
        client = get_db_client(role="detector")
        query = """
        SELECT
            triggered_at,
            rule_id,
            severity,
            asset_type,
            asset_id,
            rule_name,
            evidence_context
        FROM siem.security_alerts
        WHERE rule_id LIKE 'CORR-%'
        ORDER BY triggered_at DESC
        LIMIT 5
        """
        rows = client.query(query).result_rows
        print("\n" + "#" * 78)
        print("          LATEST CORRELATED ALERTS IN CLICKHOUSE (siem.security_alerts)")
        print("#" * 78)
        if not rows:
            print("  (No correlated alerts found yet in siem.security_alerts)")
            return

        for r in rows:
            ts, rid, sev, atype, aid, rname, ev_json = r
            print(f"  [{sev}] {rid}: {rname}")
            print(f"    Triggered At: {ts} UTC")
            print(f"    Target Asset: {atype} ({aid})")
            print("  " + "-" * 74)
    except Exception as e:
        print(f"[!] Unable to query security_alerts: {e}")


def main():
    parser = argparse.ArgumentParser(description="Correlated Attack Simulator & Verifier")
    parser.add_argument(
        "--scenario",
        choices=["1", "2", "all"],
        default="all",
        help="Attack scenario to run: 1 (VM Killchain), 2 (K8s Killchain), all (Both)",
    )
    args = parser.parse_args()

    # Ensure executable permissions
    os.chmod(VM_SCRIPT, 0o755)
    os.chmod(K8S_SCRIPT, 0o755)

    print("\n" + "#" * 78)
    print("      MINI SIEM TEMPORAL SEQUENCE CORRELATION SIMULATOR")
    print("          Powered by ClickHouse Native windowFunnel()")
    print("#" * 78)

    success_vm = False
    success_k8s = False

    if args.scenario in ("1", "all"):
        success_vm = run_cmd(["/usr/bin/env", "bash", str(VM_SCRIPT)], "Scenario 1: VM Host Compromise Kill Chain")

    if args.scenario in ("2", "all"):
        success_k8s = run_cmd(["/usr/bin/env", "bash", str(K8S_SCRIPT)], "Scenario 2: K8s Cluster Compromise Kill Chain")

    print("\n" + "=" * 78)
    print("                      EXECUTION SUMMARY")
    print("=" * 78)
    if args.scenario in ("1", "all"):
        status_vm = "[PASS] Triggered & Evaluated" if success_vm else "[FAIL] Execution Error"
        print(f"  Scenario 1 (CORR-VM-001 / Linux VM):        {status_vm}")
    if args.scenario in ("2", "all"):
        status_k8s = "[PASS] Triggered & Evaluated" if success_k8s else "[FAIL] Execution Error"
        print(f"  Scenario 2 (CORR-K8S-001 / Kubernetes):    {status_k8s}")

    display_recent_correlated_alerts()


if __name__ == "__main__":
    main()
