"""
Master Multi-Asset Telemetry Orchestrator.
Runs collectors across all 4 monitored asset classes:
 1. Host / Laptop (Process snapshot & auth sessions)
 2. Linux VM (Auditd & syslog records)
 3. Kubernetes Cluster (Kind API audit events)
 4. GitHub Repositories (Authenticated webhook events)
Ships all events to ClickHouse through the authenticated Ingestion Gateway.
"""

import sys
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

COLLECTORS = [
    ("Laptop Collector", [sys.executable, str(REPO_ROOT / "assets" / "laptop" / "collector.py"), "--once"]),
    ("Linux VM Collector", [sys.executable, str(REPO_ROOT / "assets" / "vm" / "collector.py"), "--baseline"]),
    ("Kubernetes Collector", [sys.executable, str(REPO_ROOT / "assets" / "k8s" / "collector.py"), "--baseline"]),
    ("GitHub Webhook Collector", [sys.executable, str(REPO_ROOT / "assets" / "github" / "collector.py")]),
]


def run_all():
    print("=" * 70)
    print("  Mini SIEM: Orchestrating Telemetry Ingestion (4 Asset Types)")
    print("=" * 70)

    for name, cmd in COLLECTORS:
        print(f"\n[+] Executing {name}...")
        try:
            res = subprocess.run(cmd, cwd=str(REPO_ROOT), check=True)
            print(f"[✔] {name} completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[✘] {name} failed with exit code {e.returncode}")

    print("\n" + "=" * 70)
    print("  Multi-Asset Ingestion Cycle Complete.")
    print("=" * 70)


if __name__ == "__main__":
    run_all()
