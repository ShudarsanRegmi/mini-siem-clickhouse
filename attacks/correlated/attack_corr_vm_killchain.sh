#!/usr/bin/env bash
# ==============================================================================
# Correlated Attack Scenario 1: Multi-Stage Linux Host Compromise Kill Chain
# Chain: SSH Authentication -> Sudo Privilege Escalation -> Credential Dumping (/etc/shadow)
# Correlated Rule: CORR-VM-001
# MITRE ATT&CK: T1078 (Valid Accounts) -> T1548.003 (Sudo) -> T1003.008 (/etc/shadow)
# Asset Target: Linux Virtual Machine (debianvm)
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-debianvm}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "======================================================================"
echo "[*] Launching Correlated Attack Scenario 1: Linux Host Compromise Kill Chain"
echo "[*] Target Host: ${TARGET_HOST}"
echo "[*] Chain Sequence: SSH Auth (T1078) -> Sudo Escalation (T1548.003) -> Cred Dump (T1003.008)"
echo "======================================================================"

echo ""
echo "[+] >>> STAGE 1: Remote Access / Interactive SSH Session Ingress <<<"
echo "[*] Simulating remote adversary authenticating to ${TARGET_HOST}..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${TARGET_HOST}" 'whoami && hostname && uptime'

echo ""
echo "[+] >>> STAGE 2: Privilege Escalation via Sudo Execution <<<"
echo "[*] Simulating execution of elevated root command..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${TARGET_HOST}" 'sudo /usr/bin/id'

echo ""
echo "[+] >>> STAGE 3: Credential Access / OS Shadow Dumping <<<"
echo "[*] Harvesting /etc/shadow credentials..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${TARGET_HOST}" 'sudo cat /etc/shadow | head -n 3'

echo ""
echo "[+] Step 4: Forwarding Debian VM audit telemetry to Mini SIEM Ingestion Gateway..."
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/vm/collector.py" --ssh-host 172.16.151.134 --ssh-user aparichit || python3 "${REPO_DIR}/assets/vm/collector.py" || true

echo ""
echo "[+] Step 5: Triggering Temporal Sequence Correlation Engine (CORR-VM-001)..."
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/detections/run_correlated_detections.py" --rule CORR-VM-001 --lookback 60 || python3 "${REPO_DIR}/detections/run_correlated_detections.py" --rule CORR-VM-001 --lookback 60 || true

echo ""
echo "======================================================================"
echo "[+] Correlated Scenario 1 (Linux Host Compromise) finished successfully."
echo "======================================================================"
