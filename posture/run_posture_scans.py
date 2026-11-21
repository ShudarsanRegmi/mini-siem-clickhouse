"""
Master Security Posture Orchestrator.
Executes automated vulnerability and misconfiguration scans across all 4 monitored assets:
  1. Laptop / Host Workstation
  2. Linux Virtual Machine
  3. Kubernetes Cluster
  4. GitHub Repository

Aggregates findings, validates Pydantic schemas, and ships authenticated batches
to the Mini SIEM Ingestion Gateway (/api/v1/posture).
Leverages ClickHouse ReplacingMergeTree for automatic deduplication and state updates.
"""

import os
import sys
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Any
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file, get_db_client
from posture.scanners.laptop_scanner import scan_laptop_posture
from posture.scanners.vm_scanner import scan_vm_posture
from posture.scanners.k8s_scanner import scan_k8s_posture
from posture.scanners.github_scanner import scan_github_posture

load_env_file()

GATEWAY_POSTURE_URL = os.getenv("INGESTION_POSTURE_URL", "http://127.0.0.1:8000/api/v1/posture")
BEARER_TOKEN = os.getenv("INGESTION_BEARER_TOKEN", "")


def ship_posture_findings(findings: List[Dict[str, Any]]) -> int:
    """Delivers normalized posture findings to the authenticated Gateway endpoint."""
    if not findings:
        print("[*] No findings to forward.")
        return 0

    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(GATEWAY_POSTURE_URL, json=findings, headers=headers, timeout=15)
        if resp.status_code == 201:
            inserted = resp.json().get("inserted", 0)
            print(f"[+] Successfully forwarded {inserted} posture findings to Mini SIEM Gateway.")
            return inserted
        else:
            print(f"[-] Gateway rejected posture batch ({resp.status_code}): {resp.text}")
    except Exception as e:
        print(f"[-] Network error forwarding posture findings: {e}")

    return 0


def display_posture_summary() -> None:
    """Queries ClickHouse analytical views to display current posture state."""
    try:
        client = get_db_client(role="viewer")
        summary_rows = client.query("""
            SELECT asset_type, severity, count()
            FROM siem.v_latest_posture
            WHERE status = 'OPEN'
            GROUP BY asset_type, severity
            ORDER BY asset_type, severity;
        """).result_rows

        print("\n" + "="*60)
        print("          MINI SIEM SECURITY POSTURE SUMMARY")
        print("="*60)
        print(f"{'Asset Type':<15} | {'Severity':<12} | {'Open Findings':<15}")
        print("-" * 60)
        if not summary_rows:
            print("No open posture findings found in ClickHouse.")
        for row in summary_rows:
            print(f"{row[0]:<15} | {row[1]:<12} | {row[2]:<15}")
        print("="*60 + "\n")
    except Exception as e:
        print(f"[!] Note: Could not query posture view directly: {e}")


def main():
    parser = argparse.ArgumentParser(description="Master Security Posture Orchestrator")
    parser.add_argument(
        "--asset",
        choices=["laptop", "vm", "k8s", "github", "all"],
        default="all",
        help="Target asset to scan (default: all)",
    )
    args = parser.parse_args()

    print(f"[*] Starting Security Posture Assessment cycle (target: {args.asset})...")
    start_time = datetime.datetime.now(datetime.timezone.utc)

    all_findings = []

    if args.asset in ("laptop", "all"):
        all_findings.extend(scan_laptop_posture())

    if args.asset in ("vm", "all"):
        all_findings.extend(scan_vm_posture())

    if args.asset in ("k8s", "all"):
        all_findings.extend(scan_k8s_posture())

    if args.asset in ("github", "all"):
        all_findings.extend(scan_github_posture())

    print(f"\n[*] Scan cycle finished in {(datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds():.2f}s.")
    print(f"[*] Aggregated {len(all_findings)} total posture findings across selected assets.")

    shipped = ship_posture_findings(all_findings)

    # Print ClickHouse summary
    display_posture_summary()


if __name__ == "__main__":
    main()
