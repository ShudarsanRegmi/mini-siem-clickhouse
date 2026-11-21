#!/usr/bin/env bash
# ==============================================================================
# Attack Scenario 3: Kubernetes Privileged Pod Launch & Host Root Filesystem Mount
# MITRE ATT&CK: T1610 (Deploy Container), T1611 (Escape to Host)
# Asset Target: Kubernetes Cluster (kind-siem-k8s-cluster)
#
# Execution:
#  1. Deploys pod with securityContext.privileged: true and hostPath mount to /.
#  2. Generates K8s API audit log (verb=CREATE, resource=pods, privileged=true).
#  3. Automatically deletes pod after simulation to return cluster to clean state.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/attack_3_privileged_pod.yaml"

echo "======================================================================"
echo "[*] Launching Attack Scenario 3: Privileged Pod Escape on Kubernetes"
echo "[*] MITRE ATT&CK: T1610 (Deploy Container), T1611 (Escape to Host)"
echo "======================================================================"

echo "[+] Step 1: Deploying privileged escape pod into 'default' namespace..."
kubectl apply -f "${MANIFEST}"

echo "[+] Step 2: Waiting for pod creation event to be logged by kube-apiserver..."
kubectl wait --for=condition=Initialized pod/privileged-escape-pod --timeout=15s || true

echo "[+] Step 3: Verifying pod security context..."
kubectl get pod privileged-escape-pod -o jsonpath='{.spec.containers[0].securityContext.privileged}' && echo " (Privileged: TRUE)"

echo "[+] Step 4: Cleaning up privileged pod..."
kubectl delete -f "${MANIFEST}" --ignore-not-found=true --grace-period=0 --force > /dev/null 2>&1 || true

echo "[+] Step 5: Forwarding Kubernetes audit telemetry to Mini SIEM Ingestion Gateway..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/k8s/collector.py" || python3 "${REPO_DIR}/assets/k8s/collector.py" || true

echo "[+] Attack Scenario 3 completed and cleaned up successfully."
