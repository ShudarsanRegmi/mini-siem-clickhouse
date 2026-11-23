"""
Attack Scenario 5: GitHub Secret Exfiltration / Accidental Token Leak in Commit.
MITRE ATT&CK: T1552.001 (Credentials in Files)
Asset Target: GitHub Repository (ShudarsanRegmi/mini-siem-clickhouse)

Execution:
 1. Generates an authentic canary SSH private key.
 2. Creates a unique Git branch with a 4-character random suffix (e.g. canary-leak-a3f1).
 3. Commits the private key and pushes to GitHub remote (origin).
 4. NOTE: Preserves the remote branch on GitHub for user inspection and manual deletion.
 5. Invokes the GitHub Telemetry Collector (assets/github/collector.py --branch <branch>)
    which polls the live GitHub API, inspects the commit diff patch, detects the secret leak,
    signs the authenticated webhook with HMAC-SHA256, and sends it to the SIEM gateway.
 6. Returns the local repository cleanly to 'main'.
"""

import os
import sys
import json
import secrets
import subprocess
import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file

load_env_file()

TARGET_REPO = os.getenv("GITHUB_TARGET_REPO", "ShudarsanRegmi/mini-siem-clickhouse")


def simulate_secret_leak_commit():
    # 4 random characters to guarantee unique branch name
    suffix = secrets.token_hex(2)
    branch_name = f"canary-leak-{suffix}"
    key_file = REPO_ROOT / "canary_deploy_key.pem"
    pub_file = REPO_ROOT / "canary_deploy_key.pem.pub"

    print("=" * 70)
    print(f"[*] Launching Attack Scenario 5: Real Secret Leak on Branch '{branch_name}'")
    print(f"[*] Target GitHub Repository: https://github.com/{TARGET_REPO}")
    print("[*] MITRE ATT&CK: T1552.001 (Credentials in Files)")
    print("=" * 70)

    try:
        # Step 1: Create unique local branch
        print(f"[+] Step 1: Creating unique local git branch '{branch_name}'...")
        subprocess.run(["git", "checkout", "-b", branch_name], check=True, cwd=str(REPO_ROOT))

        # Step 2: Generate authentic ED25519 canary private key pair
        print(f"[+] Step 2: Generating authentic ED25519 canary SSH private key...")
        if key_file.exists():
            key_file.unlink()
        if pub_file.exists():
            pub_file.unlink()

        keygen_cmd = [
            "ssh-keygen", "-t", "ed25519", "-N", "",
            "-f", str(key_file),
            "-C", f"canary-token-{suffix}@company.internal"
        ]
        subprocess.run(keygen_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Step 3: Stage and commit private key
        commit_msg = f"feat(ci): add staging deploy private key [canary-{suffix}]"
        print(f"[+] Step 3: Committing private key: '{commit_msg}'...")
        subprocess.run(["git", "add", "-f", str(key_file)], check=True, cwd=str(REPO_ROOT))
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, cwd=str(REPO_ROOT))

        # Step 4: Push to remote GitHub
        print(f"[+] Step 4: Pushing branch '{branch_name}' to GitHub remote (origin)...")
        subprocess.run(["git", "push", "origin", branch_name], check=True, cwd=str(REPO_ROOT))
        print(f"[+] Successfully pushed commit to GitHub remote!")
        print(f"    Branch URL: https://github.com/{TARGET_REPO}/tree/{branch_name}")
        print(f"    (Note: This remote branch is preserved for your manual inspection and deletion.)")

        # Step 5: Run the GitHub collector to poll and ingest the live commit
        print(f"[+] Step 5: Invoking GitHub Telemetry Collector for branch '{branch_name}'...")
        collector_script = REPO_ROOT / "assets" / "github" / "collector.py"
        subprocess.run([sys.executable, str(collector_script), "--branch", branch_name], check=True, cwd=str(REPO_ROOT))

        # Step 6: Trigger Detection Engine to analyze newly ingested audit telemetry
        print(f"[+] Step 6: Triggering Detection Engine to evaluate rules against ClickHouse...")
        try:
            from detections.engine import evaluate_rules
            fired = evaluate_rules(lookback_minutes=60)
            print(f"[+] Detection Engine evaluated all rules and fired {fired} new alert(s)!")
        except Exception as e:
            print(f"[!] Note evaluating detection engine: {e}")

        print("[+] Attack Scenario 5 completed successfully.")

    finally:
        # Step 7: Return local working tree cleanly to main
        print("[+] Step 7: Restoring local repository to branch 'main'...")
        subprocess.run(["git", "checkout", "main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(REPO_ROOT))
        subprocess.run(["git", "branch", "-D", branch_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(REPO_ROOT))
        if key_file.exists():
            key_file.unlink()
        if pub_file.exists():
            pub_file.unlink()
        print(f"[+] Local repository clean on 'main'. Remote branch '{branch_name}' remains live on GitHub.")


if __name__ == "__main__":
    simulate_secret_leak_commit()
