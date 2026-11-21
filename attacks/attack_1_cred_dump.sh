#!/usr/bin/env bash
# ==============================================================================
# Attack Scenario 1: Linux VM Credential Access / OS Credential Dumping
# MITRE ATT&CK: T1003 (OS Credential Dumping)
# Asset Target: Linux Virtual Machine (debianvm)
#
# Execution:
#  1. Attempts unauthorized access to /etc/shadow as unprivileged user (Permission Denied).
#  2. Executes sudo read on /etc/shadow simulating credential harvesting.
#  3. Triggers auditd rule (key="shadow_access") and auth.log sudo audit.
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-debianvm}"

echo "======================================================================"
echo "[*] Launching Attack Scenario 1: Credential Access on ${TARGET_HOST}"
echo "[*] MITRE ATT&CK: T1003 (OS Credential Dumping)"
echo "======================================================================"

echo "[+] Step 1: Simulating unprivileged read attempt on /etc/shadow..."
ssh "${TARGET_HOST}" 'cat /etc/shadow 2>&1 || true'

echo "[+] Step 2: Simulating privileged credential dump via sudo /bin/cat /etc/shadow..."
ssh "${TARGET_HOST}" 'sudo cat /etc/shadow | head -n 3'

echo "[+] Step 3: Verifying audit trail generated on ${TARGET_HOST}..."
ssh "${TARGET_HOST}" 'sudo tail -n 10 /var/log/audit/audit.log | grep -E "shadow|USER_CMD"' || true

echo "[+] Step 4: Forwarding Debian VM audit telemetry to Mini SIEM Ingestion Gateway..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/vm/collector.py" --ssh-host 172.16.151.134 --ssh-user aparichit || python3 "${REPO_DIR}/assets/vm/collector.py" || true

echo "[+] Attack Scenario 1 completed successfully."
