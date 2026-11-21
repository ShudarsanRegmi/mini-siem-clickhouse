"""
Laptop / Host Workstation Security Posture Scanner.
Audits host operating system, filesystem permissions, SSH configurations,
and local package dependencies against CIS Benchmark recommendations.
"""

import os
import sys
import socket
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HOSTNAME = socket.gethostname()


def audit_filesystem_permissions() -> List[Dict[str, Any]]:
    """Checks for sensitive file misconfigurations (e.g. world-writable /etc/shadow or /etc/passwd)."""
    findings = []
    checks = [
        {"path": "/etc/shadow", "max_perm": 0o640, "check_id": "CIS-HOST-1.1", "title": "Insecure /etc/shadow File Permissions", "severity": "CRITICAL"},
        {"path": "/etc/passwd", "max_perm": 0o644, "check_id": "CIS-HOST-1.2", "title": "Insecure /etc/passwd File Permissions", "severity": "HIGH"},
        {"path": "/etc/sudoers", "max_perm": 0o440, "check_id": "CIS-HOST-1.3", "title": "Insecure /etc/sudoers Permissions", "severity": "HIGH"},
    ]

    for item in checks:
        p = Path(item["path"])
        if p.exists():
            st = p.stat()
            mode = st.st_mode & 0o777
            # World writable check
            if mode & 0o002:
                findings.append({
                    "asset_type": "laptop",
                    "asset_id": HOSTNAME,
                    "scanner_tool": "host-cis-auditor",
                    "finding_type": "misconfiguration",
                    "check_id": item["check_id"],
                    "title": item["title"],
                    "severity": item["severity"],
                    "status": "OPEN",
                    "remediation": f"Run 'sudo chmod {oct(item['max_perm'])[2:]} {item['path']}'",
                    "details": f"File {item['path']} has mode {oct(mode)}, which permits world-writable modifications.",
                })
    return findings


def audit_kernel_hardening() -> List[Dict[str, Any]]:
    """Checks kernel security parameters via sysctl."""
    findings = []
    
    # 1. Core dump restriction check
    try:
        val = subprocess.check_output(["sysctl", "-n", "fs.suid_dumpable"], universal_newlines=True, timeout=2).strip()
        if val != "0":
            findings.append({
                "asset_type": "laptop",
                "asset_id": HOSTNAME,
                "scanner_tool": "host-cis-auditor",
                "finding_type": "misconfiguration",
                "check_id": "CIS-HOST-2.1",
                "title": "SUID Process Core Dumps Enabled",
                "severity": "MEDIUM",
                "status": "OPEN",
                "remediation": "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-security.conf and reload with 'sysctl -p'",
                "details": f"fs.suid_dumpable is currently set to '{val}'. Permitting SUID core dumps can leak process credentials.",
            })
    except Exception:
        pass

    # 2. ASLR check
    try:
        val = subprocess.check_output(["sysctl", "-n", "kernel.randomize_va_space"], universal_newlines=True, timeout=2).strip()
        if val != "2":
            findings.append({
                "asset_type": "laptop",
                "asset_id": HOSTNAME,
                "scanner_tool": "host-cis-auditor",
                "finding_type": "misconfiguration",
                "check_id": "CIS-HOST-2.2",
                "title": "Address Space Layout Randomization (ASLR) Incomplete",
                "severity": "HIGH",
                "status": "OPEN",
                "remediation": "Set 'kernel.randomize_va_space = 2' in sysctl configuration",
                "details": f"kernel.randomize_va_space is set to '{val}' instead of 2 (full randomization).",
            })
    except Exception:
        pass

    return findings


def audit_package_vulnerabilities() -> List[Dict[str, Any]]:
    """Checks local python/application dependencies for known CVEs."""
    findings = []
    # Known high-profile vulnerability baseline checks for older dependencies
    # E.g. urllib3 < 2.0.7 (CVE-2023-45803), certifi < 2023.7.22 (CVE-2023-37920), requests < 2.31.0
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=json"], universal_newlines=True, timeout=5)
        pkgs = {p["name"].lower(): p["version"] for p in json.loads(out)}

        # Sample vulnerability rule checks
        if "urllib3" in pkgs:
            ver = pkgs["urllib3"]
            if ver.startswith("1.26.") and int(ver.split(".")[2]) < 18:
                findings.append({
                    "asset_type": "laptop",
                    "asset_id": HOSTNAME,
                    "scanner_tool": "trivy-pip-auditor",
                    "finding_type": "vulnerability",
                    "check_id": "CVE-2023-45803",
                    "title": f"urllib3 Request Body Leak Vulnerability ({ver})",
                    "severity": "MEDIUM",
                    "status": "OPEN",
                    "remediation": "Upgrade urllib3 to >= 1.26.18 or >= 2.0.7",
                    "details": f"Installed urllib3 version {ver} is vulnerable to stream leakage on 303 redirects.",
                })

        if "jinja2" in pkgs:
            ver = pkgs["jinja2"]
            if ver < "3.1.3":
                findings.append({
                    "asset_type": "laptop",
                    "asset_id": HOSTNAME,
                    "scanner_tool": "trivy-pip-auditor",
                    "finding_type": "vulnerability",
                    "check_id": "CVE-2024-22195",
                    "title": f"Jinja2 Compiler XSS Vulnerability ({ver})",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "remediation": "Upgrade jinja2 to >= 3.1.3",
                    "details": f"Jinja2 version {ver} has an HTML attribute injection flaw in xmlattr filter.",
                })
    except Exception as e:
        print(f"[!] Warning checking package vulnerabilities: {e}")

    return findings


def scan_laptop_posture() -> List[Dict[str, Any]]:
    """Aggregates all laptop posture findings."""
    print(f"[*] Scanning Laptop security posture on '{HOSTNAME}'...")
    findings = []
    findings.extend(audit_filesystem_permissions())
    findings.extend(audit_kernel_hardening())
    findings.extend(audit_package_vulnerabilities())
    print(f"[+] Found {len(findings)} posture findings for Laptop.")
    return findings


if __name__ == "__main__":
    results = scan_laptop_posture()
    print(json.dumps(results, indent=2))
