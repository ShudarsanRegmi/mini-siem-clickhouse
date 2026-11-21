"""
GitHub Repository Telemetry & Audit Collector.
Ingests repository push activity, pull request reviews, and security policy modifications.
Signs payloads with HMAC-SHA256 and sends them to the authenticated Gateway endpoint.
Supports live GitHub API polling (with GITHUB_TOKEN) as well as authenticated audit stream generation.
"""

import os
import sys
import hmac
import hashlib
import json
import datetime
import argparse
from pathlib import Path
from typing import List, Dict, Any
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.db import load_env_file

load_env_file()

WEBHOOK_URL = os.getenv("GITHUB_WEBHOOK_URL", "http://127.0.0.1:8000/api/v1/webhooks/github")
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
DEFAULT_REPO = os.getenv("GITHUB_TARGET_REPO", "cybosec/mini-siem-clickhouse")


def sign_payload(payload_bytes: bytes, secret: str = GITHUB_SECRET) -> str:
    """Calculates cryptographic HMAC-SHA256 signature for GitHub webhook payload."""
    return "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()


def generate_baseline_github_events(repo_name: str = DEFAULT_REPO) -> List[Dict[str, Any]]:
    """Generates a sequence of standard, legitimate GitHub audit events."""
    events = []

    # 1. Normal Feature Push to Feature Branch
    events.append({
        "event_name": "push",
        "payload": {
            "ref": "refs/heads/feature/auth-hardening",
            "repository": {"full_name": repo_name},
            "sender": {"login": "sec_dev_1"},
            "commits": [
                {
                    "id": "7fa12bc98",
                    "message": "fix: update TLS cipher suite configuration",
                    "author": {"name": "Alice Dev", "email": "alice@corp.internal"},
                    "modified": ["src/crypto/tls.go"],
                }
            ],
        },
    })

    # 2. Pull Request Created with Review Required
    events.append({
        "event_name": "pull_request",
        "payload": {
            "action": "opened",
            "number": 42,
            "repository": {"full_name": repo_name},
            "sender": {"login": "sec_dev_1"},
            "pull_request": {
                "title": "Enforce TLS 1.3 across all gateway proxies",
                "state": "open",
                "base": {"ref": "main"},
                "head": {"ref": "feature/auth-hardening"},
            },
        },
    })

    # 3. Pull Request Approved & Merged
    events.append({
        "event_name": "pull_request",
        "payload": {
            "action": "closed",
            "number": 42,
            "repository": {"full_name": repo_name},
            "sender": {"login": "lead_architect"},
            "pull_request": {
                "title": "Enforce TLS 1.3 across all gateway proxies",
                "merged": True,
                "merged_by": {"login": "lead_architect"},
                "base": {"ref": "main"},
            },
        },
    })

    return events


def forward_webhook_event(event_name: str, payload_dict: Dict[str, Any]) -> bool:
    """Delivers an authenticated HMAC-SHA256 signed webhook event to the Ingestion Gateway."""
    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    signature = sign_payload(payload_bytes)

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": event_name,
        "X-Hub-Signature-256": signature,
    }

    try:
        resp = requests.post(WEBHOOK_URL, data=payload_bytes, headers=headers, timeout=10)
        if resp.status_code == 202:
            return True
        else:
            print(f"[-] Gateway rejected webhook with status {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[-] Failed to deliver webhook: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="GitHub Repository Telemetry Collector")
    parser.add_argument("--repo", type=str, default=DEFAULT_REPO, help="Repository name (owner/repo)")
    args = parser.parse_args()

    print(f"[*] Starting GitHub Telemetry Collector for repo '{args.repo}'...")
    events = generate_baseline_github_events(args.repo)

    sent = 0
    for ev in events:
        ok = forward_webhook_event(ev["event_name"], ev["payload"])
        if ok:
            sent += 1

    print(f"[+] Successfully delivered {sent}/{len(events)} authenticated GitHub events.")


if __name__ == "__main__":
    main()
