"""
Linux VM Security & Auditd Telemetry Collector.
Ingests Linux VM authentication records, sudo executions, auditd events, and network connections.
Supports live /var/log/auth.log tailing as well as simulated baseline audit generation.
Ships authenticated batches to the Mini SIEM Ingestion Gateway.
"""

import os
import sys
import re
import socket
import datetime
import json
import subprocess
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
VM_ASSET_ID = os.getenv("VM_ASSET_ID", "prod-linux-vm-01")


def generate_baseline_vm_telemetry() -> List[Dict[str, Any]]:
    """
    Generates standard baseline VM audit events:
    - SSH authentications (successful & routine rejected probes)
    - Sudo command invocations
    - Cron job executions
    - Daemon process heartbeats
    """
    events = []
    base_time = datetime.datetime.now(datetime.timezone.utc)

    # 1. SSH Accepted Publickey
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=15)).isoformat(),
        "asset_type": "vm",
        "asset_id": VM_ASSET_ID,
        "event_category": "auth",
        "event_type": "ssh_login_success",
        "severity": "INFO",
        "actor": "devops_engineer",
        "source_ip": "10.0.1.45",
        "process_name": "sshd",
        "command_line": "sshd: devops_engineer [priv]",
        "target_resource": "ssh-session-pts/0",
        "raw_json": json.dumps({"auth_method": "publickey", "port": 54221, "fingerprint": "SHA256:abc12345"}),
    })

    # 2. Sudo Command Execution (Legitimate admin task)
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=12)).isoformat(),
        "asset_type": "vm",
        "asset_id": VM_ASSET_ID,
        "event_category": "privilege",
        "event_type": "sudo_command",
        "severity": "LOW",
        "actor": "devops_engineer",
        "source_ip": "10.0.1.45",
        "process_name": "sudo",
        "command_line": "sudo systemctl status nginx",
        "target_resource": "/bin/systemctl",
        "raw_json": json.dumps({"pwd": "/home/devops_engineer", "command": "systemctl status nginx"}),
    })

    # 3. Scheduled Cron Job (Logrotate)
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=5)).isoformat(),
        "asset_type": "vm",
        "asset_id": VM_ASSET_ID,
        "event_category": "process",
        "event_type": "cron_job_executed",
        "severity": "INFO",
        "actor": "root",
        "source_ip": "127.0.0.1",
        "process_name": "cron",
        "command_line": "/usr/sbin/logrotate /etc/logrotate.conf",
        "target_resource": "/etc/logrotate.conf",
        "raw_json": json.dumps({"job": "logrotate", "schedule": "daily"}),
    })

    # 4. Outbound HTTPS Connection (Package repository check)
    events.append({
        "timestamp": (base_time - datetime.timedelta(minutes=2)).isoformat(),
        "asset_type": "vm",
        "asset_id": VM_ASSET_ID,
        "event_category": "network",
        "event_type": "outbound_connection",
        "severity": "INFO",
        "actor": "apt",
        "source_ip": "10.0.1.10",
        "process_name": "apt-get",
        "command_line": "apt-get update",
        "target_resource": "archive.ubuntu.com:80",
        "raw_json": json.dumps({"dest_ip": "91.189.91.39", "dest_port": 80, "protocol": "TCP"}),
    })

    return events


def parse_auth_log_line(line: str) -> Dict[str, Any]:
    """Parses a standard Linux auth.log line into a TelemetryEvent."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    actor = "root" if "root" in line else "unknown"
    severity = "INFO"

    if "Failed password" in line or "authentication failure" in line:
        event_type = "auth_failure"
        severity = "MEDIUM"
    elif "Accepted" in line:
        event_type = "auth_success"
    elif "sudo:" in line:
        event_type = "sudo_execution"
        severity = "LOW"
    else:
        event_type = "auth_event"

    return {
        "timestamp": now,
        "asset_type": "vm",
        "asset_id": VM_ASSET_ID,
        "event_category": "auth",
        "event_type": event_type,
        "severity": severity,
        "actor": actor,
        "source_ip": "127.0.0.1",
        "process_name": "syslog",
        "command_line": line[:1024],
        "target_resource": "auth.log",
        "raw_json": json.dumps({"log": line}),
    }


def ship_telemetry(events: List[Dict[str, Any]]) -> int:
    """Sends telemetry batch to the authenticated ingestion gateway."""
    if not events:
        return 0

    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(GATEWAY_URL, json=events, headers=headers, timeout=10)
        if resp.status_code == 201:
            return resp.json().get("inserted", 0)
        else:
            print(f"[-] Gateway returned error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[-] Network error shipping VM telemetry: {e}")

    return 0


def collect_remote_ssh_logs(host: str, user: str, key_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches real auth and journal security logs from remote Linux VM via SSH."""
    events = []
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
    ]
    if key_path:
        ssh_cmd.extend(["-i", key_path])

    remote_target = f"{user}@{host}"
    remote_command = "journalctl -u ssh -n 100 --no-pager 2>/dev/null || cat /var/log/auth.log 2>/dev/null | tail -n 100"

    try:
        output = subprocess.check_output(
            ssh_cmd + [remote_target, remote_command],
            universal_newlines=True,
            timeout=10,
        )
        for line in output.splitlines():
            line = line.strip()
            if line:
                events.append(parse_auth_log_line(line))
        print(f"[+] Successfully pulled {len(events)} security log lines from VM {host} via SSH.")
    except Exception as e:
        print(f"[!] Warning: SSH remote log collection failed: {e}. Falling back to baseline simulation.")
        return generate_baseline_vm_telemetry()

    return events if events else generate_baseline_vm_telemetry()


def main():
    parser = argparse.ArgumentParser(description="Linux VM Telemetry Collector")
    parser.add_argument("--baseline", action="store_true", help="Generate and ship baseline VM audit telemetry")
    parser.add_argument("--log-file", type=str, help="Path to auth.log to parse and ship")
    parser.add_argument("--ssh-host", type=str, help="IP or hostname of remote Linux VM to pull logs from")
    parser.add_argument("--ssh-user", type=str, default="aparichit", help="SSH user on remote VM")
    parser.add_argument("--ssh-key", type=str, help="Path to SSH private key for remote VM")
    args = parser.parse_args()

    print(f"[*] Starting Linux VM Telemetry Collector for asset '{VM_ASSET_ID}'...")

    events = []
    if args.ssh_host:
        events = collect_remote_ssh_logs(args.ssh_host, args.ssh_user, args.ssh_key)
    elif args.log_file and os.path.exists(args.log_file):
        print(f"[*] Reading auth log file: {args.log_file}")
        with open(args.log_file, "r") as f:
            for line in f:
                if line.strip():
                    events.append(parse_auth_log_line(line.strip()))
    else:
        events = generate_baseline_vm_telemetry()

    shipped = ship_telemetry(events)
    print(f"[+] Successfully forwarded {shipped} VM telemetry events to ClickHouse.")


if __name__ == "__main__":
    main()
