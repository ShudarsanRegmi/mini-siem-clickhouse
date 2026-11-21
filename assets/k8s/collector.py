"""
Kubernetes Cluster Audit & Telemetry Collector.
Parses Kubernetes API Server Audit Logs (from Kind or cloud managed clusters).
Extracts:
 - User / ServiceAccount identities (actor)
 - Source IP addresses
 - High-risk actions: pod exec, secret access, privileged container deployments
Forward normalized events to the Mini SIEM Ingestion Gateway.
"""

import os
import sys
import json
import datetime
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file

load_env_file()

GATEWAY_URL = os.getenv("INGESTION_GATEWAY_URL", "http://127.0.0.1:8000/api/v1/telemetry")
BEARER_TOKEN = os.getenv("INGESTION_BEARER_TOKEN", "")
K8S_ASSET_ID = os.getenv("K8S_ASSET_ID", "kind-siem-k8s")
AUDIT_LOG_FILE = os.getenv("K8S_AUDIT_LOG_PATH", str(REPO_ROOT / ".audit" / "kube-audit.log"))


def parse_k8s_audit_record(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parses a single Kubernetes API audit JSON event into a standard TelemetryEvent."""
    try:
        verb = record.get("verb", "unknown")
        user = record.get("user", {}).get("username", "system:anonymous")
        source_ips = record.get("sourceIPs", [])
        source_ip = source_ips[0] if source_ips else "127.0.0.1"

        obj_ref = record.get("objectRef", {})
        resource = obj_ref.get("resource", "unknown")
        subresource = obj_ref.get("subresource", "")
        namespace = obj_ref.get("namespace", "default")
        name = obj_ref.get("name", "")

        event_type = f"{verb}_{resource}"
        if subresource:
            event_type = f"{verb}_{resource}_{subresource}"

        target = f"{namespace}/{resource}/{name}" if name else f"{namespace}/{resource}"

        # Severity Assessment
        severity = "INFO"
        if subresource == "exec":
            severity = "HIGH"
        elif resource in ("secrets", "clusterrolebindings") and verb in ("create", "delete", "patch"):
            severity = "MEDIUM"

        # Check for privileged container creation
        req_obj = record.get("requestObject", {})
        spec = req_obj.get("spec", {})
        containers = spec.get("containers", [])
        is_privileged = any(
            c.get("securityContext", {}).get("privileged", False) for c in containers
        )
        if is_privileged:
            severity = "CRITICAL"
            event_type = "create_privileged_pod"

        ts_str = record.get("stageTimestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "timestamp": ts_str,
            "asset_type": "k8s",
            "asset_id": K8S_ASSET_ID,
            "event_category": "k8s_audit",
            "event_type": event_type,
            "severity": severity,
            "actor": user,
            "source_ip": source_ip,
            "process_name": "kube-apiserver",
            "command_line": f"K8s API {verb.upper()} {target}",
            "target_resource": target,
            "raw_json": json.dumps(record),
        }
    except Exception as e:
        print(f"[!] Error parsing audit record: {e}")
        return None


def generate_baseline_k8s_telemetry() -> List[Dict[str, Any]]:
    """Generates standard baseline Kubernetes API audit telemetry."""
    base_time = datetime.datetime.now(datetime.timezone.utc)
    events = []

    # 1. Routine Deployment Scale / Metadata Check
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=10)).isoformat(),
        "asset_type": "k8s",
        "asset_id": K8S_ASSET_ID,
        "event_category": "k8s_audit",
        "event_type": "get_pods",
        "severity": "INFO",
        "actor": "system:serviceaccount:kube-system:generic-garbage-collector",
        "source_ip": "10.244.0.1",
        "process_name": "kube-apiserver",
        "command_line": "K8s API GET kube-system/pods",
        "target_resource": "kube-system/pods",
        "raw_json": json.dumps({"verb": "get", "resource": "pods", "namespace": "kube-system"}),
    })

    # 2. ConfigMap Read by Application Pod
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=8)).isoformat(),
        "asset_type": "k8s",
        "asset_id": K8S_ASSET_ID,
        "event_category": "k8s_audit",
        "event_type": "get_configmaps",
        "severity": "INFO",
        "actor": "system:serviceaccount:default:web-service-account",
        "source_ip": "10.244.0.14",
        "process_name": "kube-apiserver",
        "command_line": "K8s API GET default/configmaps/app-config",
        "target_resource": "default/configmaps/app-config",
        "raw_json": json.dumps({"verb": "get", "resource": "configmaps", "name": "app-config"}),
    })

    # 3. Microservice Pod Lifecycle (Standard ReplicaSet creation)
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=4)).isoformat(),
        "asset_type": "k8s",
        "asset_id": K8S_ASSET_ID,
        "event_category": "k8s_audit",
        "event_type": "create_pods",
        "severity": "INFO",
        "actor": "system:serviceaccount:kube-system:replicaset-controller",
        "source_ip": "127.0.0.1",
        "process_name": "kube-apiserver",
        "command_line": "K8s API CREATE default/pods/frontend-78b9487f9-8x2k1",
        "target_resource": "default/pods/frontend-78b9487f9-8x2k1",
        "raw_json": json.dumps({"spec": {"containers": [{"name": "frontend", "image": "nginx:alpine"}]}}),
    })

    return events


def ship_telemetry(events: List[Dict[str, Any]]) -> int:
    if not events:
        return 0

    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json",
    }

    chunk_size = 200
    total_shipped = 0

    for i in range(0, len(events), chunk_size):
        chunk = events[i : i + chunk_size]
        try:
            resp = requests.post(GATEWAY_URL, json=chunk, headers=headers, timeout=15)
            if resp.status_code == 201:
                total_shipped += resp.json().get("inserted", 0)
            else:
                print(f"[-] Gateway returned error {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[-] Network error shipping K8s telemetry chunk {i//chunk_size + 1}: {e}")

    return total_shipped


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Audit Telemetry Collector")
    parser.add_argument("--baseline", action="store_true", help="Generate and ship baseline K8s audit telemetry")
    parser.add_argument("--audit-file", type=str, default=AUDIT_LOG_FILE, help="Path to kube-audit.log")
    args = parser.parse_args()

    print(f"[*] Starting Kubernetes Telemetry Collector for cluster '{K8S_ASSET_ID}'...")

    events = []
    if os.path.exists(args.audit_file) and os.path.getsize(args.audit_file) > 0 and not args.baseline:
        print(f"[*] Parsing audit log file: {args.audit_file}")
        with open(args.audit_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        record = json.loads(line.strip())
                        ev = parse_k8s_audit_record(record)
                        if ev:
                            events.append(ev)
                    except json.JSONDecodeError:
                        continue
    else:
        events = generate_baseline_k8s_telemetry()

    shipped = ship_telemetry(events)
    print(f"[+] Successfully forwarded {shipped} Kubernetes audit events to ClickHouse.")


if __name__ == "__main__":
    main()
