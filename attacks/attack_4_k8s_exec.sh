#!/usr/bin/env bash
# ==============================================================================
# Attack Scenario 4: Kubernetes Interactive Pod Exec & Token Snooping
# MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1552.007 (Container Credentials)
# Asset Target: Kubernetes Cluster (kind-siem-k8s-cluster)
#
# Execution:
#  1. Ensures a target pod is active in namespace 'default'.
#  2. Executes kubectl exec into the pod to inspect ServiceAccount tokens.
#  3. Generates high-risk K8s API audit log (verb=CREATE, resource=pods, subresource=exec).
#  4. Automatically cleans up target pod.
# ==============================================================================

set -euo pipefail

TARGET_POD="victim-target-app"
NAMESPACE="default"

echo "======================================================================"
echo "[*] Launching Attack Scenario 4: Unauthorized Pod Exec & Token Snooping"
echo "[*] MITRE ATT&CK: T1059 (Execution), T1552.007 (Container Credentials)"
echo "======================================================================"

echo "[+] Step 1: Starting victim target pod '${TARGET_POD}' in namespace '${NAMESPACE}'..."
kubectl run "${TARGET_POD}" --image=busybox:1.36 --restart=Never -n "${NAMESPACE}" -- sleep 60 > /dev/null 2>&1 || true

echo "[+] Step 2: Waiting for target pod to be Running..."
kubectl wait --for=condition=Ready "pod/${TARGET_POD}" -n "${NAMESPACE}" --timeout=20s || sleep 5

echo "[+] Step 3: Simulating attacker interactive exec & ServiceAccount token harvest..."
kubectl exec -i "${TARGET_POD}" -n "${NAMESPACE}" -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/ || true

echo "[+] Step 4: Reading ServiceAccount token via exec..."
kubectl exec -i "${TARGET_POD}" -n "${NAMESPACE}" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c 1-25 && echo " [TRUNCATED SERVICEACCOUNT JWT TOKEN]"

echo "[+] Step 5: Cleaning up victim target pod..."
kubectl delete pod "${TARGET_POD}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force > /dev/null 2>&1 || true

echo "[+] Step 6: Forwarding Kubernetes audit telemetry to Mini SIEM Ingestion Gateway..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/k8s/collector.py" || python3 "${REPO_DIR}/assets/k8s/collector.py" || true

echo "[+] Attack Scenario 4 completed and cleaned up successfully."
