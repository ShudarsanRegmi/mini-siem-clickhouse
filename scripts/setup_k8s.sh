#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CLUSTER_NAME="siem-k8s-cluster"
AUDIT_DIR="$REPO_ROOT/.audit"

mkdir -p "$AUDIT_DIR"
touch "$AUDIT_DIR/kube-audit.log"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "[+] Kind cluster '${CLUSTER_NAME}' is already active."
else
    echo "[*] Creating Kind cluster '${CLUSTER_NAME}' with Kube-API Audit Logging enabled..."
    kind create cluster --config assets/k8s/kind-config.yaml
    echo "[+] Kind cluster '${CLUSTER_NAME}' created successfully."
fi

# Verify cluster connectivity
kubectl cluster-info --context "kind-${CLUSTER_NAME}"
echo "[+] Kubernetes context ready and audit logging configured."
