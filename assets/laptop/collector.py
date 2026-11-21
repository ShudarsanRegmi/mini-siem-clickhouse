"""
Host / Laptop Security Telemetry Collector.
Captures endpoint process executions, auth state, and system telemetry.
Applies Defense-in-Depth sanitization to mask passwords/tokens in command lines.
Ships authenticated batches to the Mini SIEM Ingestion Gateway.
"""

import os
import sys
import re
import socket
import subprocess
import datetime
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
import requests

# Ensure repo root is available
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file

load_env_file()

GATEWAY_URL = os.getenv("INGESTION_GATEWAY_URL", "http://127.0.0.1:8000/api/v1/telemetry")
BEARER_TOKEN = os.getenv("INGESTION_BEARER_TOKEN", "")
HOSTNAME = socket.gethostname()

# Regex patterns to sanitize credentials from command line strings
SENSITIVE_PATTERNS = [
    re.compile(r"(password|passwd|pwd|token|secret|key|api_key)=([^\s]+)", re.IGNORECASE),
    re.compile(r"(--password|--token|--secret)\s+([^\s]+)", re.IGNORECASE),
]


def sanitize_cmdline(cmd: str) -> str:
    """Masks potential credentials in command lines before ingestion."""
    sanitized = cmd
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r"\1=[REDACTED]", sanitized)
    return sanitized


def collect_running_processes() -> List[Dict[str, Any]]:
    """Captures currently running processes via ps command."""
    events = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        output = subprocess.check_output(
            ["ps", "-eo", "pid,user,comm,args", "--no-headers"],
            universal_newlines=True,
            timeout=5,
        )
    except Exception as e:
        print(f"[!] Warning: Failed to inspect process table: {e}")
        return []

    for line in output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue
        pid, user, comm = parts[0], parts[1], parts[2]
        args = parts[3] if len(parts) >= 4 else comm

        # Exclude kernel threads and system daemons
        if comm.startswith("[") or pid in ("1", "2"):
            continue

        sanitized_args = sanitize_cmdline(args)
        severity = "INFO"

        # Highlight security-relevant processes
        if comm in ("sudo", "su", "iptables", "nmap", "nc", "netcat", "curl", "wget", "bash", "sh"):
            severity = "LOW"

        events.append({
            "timestamp": now,
            "asset_type": "laptop",
            "asset_id": HOSTNAME,
            "event_category": "process",
            "event_type": "process_snapshot",
            "severity": severity,
            "actor": user,
            "source_ip": "127.0.0.1",
            "process_name": comm,
            "command_line": sanitized_args[:1024],
            "target_resource": f"PID:{pid}",
            "raw_json": json.dumps({"pid": pid, "comm": comm, "user": user}),
        })

    return events


def collect_auth_telemetry() -> List[Dict[str, Any]]:
    """Captures logged in users and terminal sessions."""
    events = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        who_output = subprocess.check_output(["who"], universal_newlines=True, timeout=5)
        for line in who_output.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            user = parts[0]
            tty = parts[1] if len(parts) > 1 else "unknown"
            events.append({
                "timestamp": now,
                "asset_type": "laptop",
                "asset_id": HOSTNAME,
                "event_category": "auth",
                "event_type": "active_session",
                "severity": "INFO",
                "actor": user,
                "source_ip": "127.0.0.1",
                "process_name": "login",
                "command_line": f"Session on {tty}",
                "target_resource": tty,
                "raw_json": json.dumps({"user": user, "tty": tty}),
            })
    except Exception:
        pass

    return events


def ship_telemetry(events: List[Dict[str, Any]]) -> int:
    """Sends telemetry batch to the authenticated ingestion gateway."""
    if not events:
        return 0

    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json",
    }

    # Transmit in chunks of 500 to stay well below DoS batch limit
    chunk_size = 500
    total_shipped = 0

    for i in range(0, len(events), chunk_size):
        chunk = events[i : i + chunk_size]
        try:
            resp = requests.post(GATEWAY_URL, json=chunk, headers=headers, timeout=10)
            if resp.status_code == 201:
                total_shipped += resp.json().get("inserted", 0)
            else:
                print(f"[-] Gateway returned error {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[-] Network error shipping telemetry: {e}")

    return total_shipped


def main():
    parser = argparse.ArgumentParser(description="Laptop Security Telemetry Collector")
    parser.add_argument("--once", action="store_true", help="Run a single collection cycle and exit")
    args = parser.parse_args()

    print(f"[*] Starting Laptop Telemetry Collector on host '{HOSTNAME}'...")
    events = collect_running_processes() + collect_auth_telemetry()
    print(f"[*] Collected {len(events)} events from host.")
    shipped = ship_telemetry(events)
    print(f"[+] Successfully forwarded {shipped} host telemetry events to ClickHouse.")


if __name__ == "__main__":
    main()
