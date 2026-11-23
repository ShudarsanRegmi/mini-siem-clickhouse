#!/usr/bin/env bash
# ==============================================================================
# Correlated Attack Scenario 2: Multi-Stage Kubernetes Cluster Compromise Kill Chain
# Chain: Interactive Pod Exec -> Container Secret Harvest -> Privileged Host Escape Pod
# Correlated Rule: CORR-K8S-001
# MITRE ATT&CK: T1059 (Execution) -> T1552.007 (Credentials) -> T1611 (Escape to Host)
# Asset Target: Kubernetes Cluster (kind-siem-k8s)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFEST="${SCRIPT_DIR}/corr_k8s_escape_pod.yaml"
VICTIM_POD="victim-checkout-service"
NAMESPACE="default"

echo "======================================================================"
echo "[*] Launching Correlated Attack Scenario 2: Kubernetes Compromise Kill Chain"
echo "[*] Chain Sequence: Pod Exec (T1059) -> Secret Read (T1552.007) -> Host Escape (T1611)"
echo "======================================================================"

echo ""
echo "[+] Step 0: Deploying baseline unprivileged workload '${VICTIM_POD}'..."
kubectl delete pod "${VICTIM_POD}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force > /dev/null 2>&1 || true
kubectl run "${VICTIM_POD}" --image=busybox:1.36 --restart=Never -n "${NAMESPACE}" -- sleep 180 > /dev/null 2>&1
echo "[*] Waiting for '${VICTIM_POD}' to become Ready..."
kubectl wait --for=condition=Ready "pod/${VICTIM_POD}" -n "${NAMESPACE}" --timeout=25s || sleep 5

echo ""
echo "[+] >>> STAGE 1: Unauthorized Interactive Pod Execution (T1059) <<<"
echo "[*] Attacker breaches container perimeter and runs commands inside pod..."
kubectl exec -i "${VICTIM_POD}" -n "${NAMESPACE}" -- whoami
kubectl exec -i "${VICTIM_POD}" -n "${NAMESPACE}" -- uname -a

echo ""
echo "[+] >>> STAGE 2: ServiceAccount Credential Harvesting (T1552.007) <<<"
echo "[*] Attacker searches for and extracts mounted Kubernetes API tokens..."
kubectl exec -i "${VICTIM_POD}" -n "${NAMESPACE}" -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/ || true
kubectl exec -i "${VICTIM_POD}" -n "${NAMESPACE}" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c 1-25 && echo " [TRUNCATED JWT TOKEN]"
echo "[*] Attacker uses acquired permissions to inspect cluster secrets..."
kubectl get secrets -n "${NAMESPACE}" || true

echo ""
echo "[+] >>> STAGE 3: Container Escape via Privileged Pod Deployment (T1611) <<<"
echo "[*] Attacker uses compromised credentials to deploy privileged root escape pod..."
kubectl apply -f "${MANIFEST}"
echo "[*] Awaiting kube-apiserver admission and pod initialization..."
kubectl wait --for=condition=Initialized pod/k8s-killchain-escape-pod -n "${NAMESPACE}" --timeout=20s || sleep 3

echo ""
echo "[+] Step 4: Cleaning up attack artifacts to restore cluster state..."
kubectl delete pod "${VICTIM_POD}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force > /dev/null 2>&1 || true
kubectl delete -f "${MANIFEST}" --ignore-not-found=true --grace-period=0 --force > /dev/null 2>&1 || true
echo "[*] Cluster state cleaned."

echo ""
echo "[+] Step 5: Forwarding Kubernetes audit telemetry to Mini SIEM Ingestion Gateway..."
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/assets/k8s/collector.py" || python3 "${REPO_DIR}/assets/k8s/collector.py" || true

echo ""
echo "[+] Step 6: Triggering Temporal Sequence Correlation Engine (CORR-K8S-001)..."
"${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/detections/run_correlated_detections.py" --rule CORR-K8S-001 --lookback 60 || python3 "${REPO_DIR}/detections/run_correlated_detections.py" --rule CORR-K8S-001 --lookback 60 || true

echo ""
echo "======================================================================"
echo "[+] Correlated Scenario 2 (Kubernetes Compromise) finished successfully."
echo "======================================================================"
