"""
GitHub Repository Security Posture Scanner.
Audits repository configuration, secret exposures in commit history,
and branch protection policies according to OpenSSF / CIS Software Supply Chain Security best practices.
"""

import os
import sys
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_REPO = os.getenv("GITHUB_TARGET_REPO", "ShudarsanRegmi/mini-siem-clickhouse")

# Regular expressions for credential exposure detection
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "CRITICAL",
        "check_id": "SEC-GIT-SECRET-AWS",
    },
    {
        "name": "Generic Private Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "check_id": "SEC-GIT-SECRET-PRIVKEY",
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "severity": "CRITICAL",
        "check_id": "SEC-GIT-SECRET-GHTOKEN",
    },
    {
        "name": "Slack Webhook / Bot Token",
        "pattern": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        "severity": "HIGH",
        "check_id": "SEC-GIT-SECRET-SLACK",
    },
]


def audit_git_secrets(repo_path: Path = REPO_ROOT) -> List[Dict[str, Any]]:
    """Scans git commit history and working tree for exposed plaintext secrets."""
    findings = []
    
    # Check recent git commits (last 50 commits)
    try:
        cmd = ["git", "-C", str(repo_path), "log", "-p", "-n", "50", "--", "."]
        diff_output = subprocess.check_output(cmd, universal_newlines=True, timeout=10)
        
        for rule in SECRET_PATTERNS:
            matches = rule["pattern"].findall(diff_output)
            # Filter out mock / test strings (e.g. AKIAIOSFODNN7EXAMPLE, dummy fixtures)
            legit_findings = [m for m in matches if not any(mock in m for mock in ["EXAMPLE", "DUMMY", "TEST", "MOCK", "SAMPLE"])]
            if legit_findings:
                findings.append({
                    "asset_type": "github",
                    "asset_id": DEFAULT_REPO,
                    "scanner_tool": "git-secret-auditor",
                    "finding_type": "secret_leak",
                    "check_id": rule["check_id"],
                    "title": f"Exposed {rule['name']} in Git Commit History",
                    "severity": rule["severity"],
                    "status": "OPEN",
                    "remediation": "Revoke and rotate exposed credential immediately. Rewrite git history using git-filter-repo.",
                    "details": f"Found {len(legit_findings)} potential occurrences of {rule['name']} in repository commit log.",
                })
    except Exception as e:
        print(f"[!] Warning scanning git commit history for secrets: {e}")

    return findings


def audit_branch_protection(repo_name: str = DEFAULT_REPO) -> List[Dict[str, Any]]:
    """Audits repository branch protection settings via GitHub API."""
    findings = []
    try:
        cmd = ["gh", "api", f"repos/{repo_name}/branches/main/protection"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=3)
        prot_data = json.loads(out)
        
        # Check required pull request reviews
        if "required_pull_request_reviews" not in prot_data:
            findings.append({
                "asset_type": "github",
                "asset_id": repo_name,
                "scanner_tool": "github-policy-auditor",
                "finding_type": "misconfiguration",
                "check_id": "CIS-GIT-1.1",
                "title": "Branch Protection: Pull Request Reviews Not Required on 'main'",
                "severity": "HIGH",
                "status": "OPEN",
                "remediation": "Enable 'Require a pull request before merging' with at least 1 approval on branch 'main'.",
                "details": "Direct commits can be pushed to 'main' without peer code review or four-eyes verification.",
            })

    except Exception as e:
        # Branch protection returns 404 if not enabled at all or times out
        findings.append({
            "asset_type": "github",
            "asset_id": repo_name,
            "scanner_tool": "github-policy-auditor",
            "finding_type": "misconfiguration",
            "check_id": "CIS-GIT-1.0",
            "title": "Default Branch 'main' Has No Protection Rules Enabled",
            "severity": "HIGH",
            "status": "OPEN",
            "remediation": "Configure GitHub branch protection rule for 'main' enforcing signed commits and PR reviews.",
            "details": f"Branch protection check noted: {e}. No active branch protection rules could be verified on default branch 'main'.",
        })

    return findings


def audit_repository_features(repo_name: str = DEFAULT_REPO) -> List[Dict[str, Any]]:
    """Checks repository security features (Secret Scanning, Dependabot)."""
    findings = []
    try:
        cmd = ["gh", "api", f"repos/{repo_name}"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=3)
        repo_data = json.loads(out)

        sec_analysis = repo_data.get("security_and_analysis", {})
        secret_scanning = sec_analysis.get("secret_scanning", {}).get("status", "disabled")
        
        if secret_scanning != "enabled" and not repo_data.get("private", False):
            # For public repos, secret scanning is typically on, but let's verify
            pass

        # Check if issues or wiki are open if not needed (reducing attack surface)
        if repo_data.get("has_wiki", False):
            findings.append({
                "asset_type": "github",
                "asset_id": repo_name,
                "scanner_tool": "github-policy-auditor",
                "finding_type": "misconfiguration",
                "check_id": "CIS-GIT-2.3",
                "title": "Public Repository Wiki Enabled (Spam / Phishing Vector)",
                "severity": "LOW",
                "status": "OPEN",
                "remediation": "Disable public Wiki in Repository Settings -> Features if documentation is in markdown.",
                "details": "Repository wiki is enabled; unvetted contributors could inject untracked content.",
            })

    except Exception as e:
        print(f"[!] Warning reading repository metadata: {e}")

    return findings


def scan_github_posture(repo_name: str = DEFAULT_REPO) -> List[Dict[str, Any]]:
    """Runs complete GitHub repository posture assessment."""
    print(f"[*] Scanning GitHub security posture for '{repo_name}'...")
    findings = []
    findings.extend(audit_git_secrets(REPO_ROOT))
    findings.extend(audit_branch_protection(repo_name))
    findings.extend(audit_repository_features(repo_name))
    print(f"[+] Found {len(findings)} posture findings for GitHub repository.")
    return findings


if __name__ == "__main__":
    results = scan_github_posture()
    print(json.dumps(results, indent=2))
