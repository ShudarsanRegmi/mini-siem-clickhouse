# Security Review: Phase 3 (Automated Multi-Asset Posture Assessment)

**Date:** 2026-11-21  
**Target:** Vulnerability & CIS Misconfiguration Scanners (`posture/`), Master Orchestrator (`posture/run_posture_scans.py`), Deduplicating Data Model (`siem.posture_findings`)  
**Reviewer:** Antigravity Autonomous Security Engineer  

---

## 1. Scope of Review
- Scanner Components:
  - `posture/scanners/laptop_scanner.py`: CIS workstation checks (file permissions, ASLR, core dumps, package CVEs).
  - `posture/scanners/vm_scanner.py`: CIS Linux Server benchmarks (sshd_config, cron security, kernel vulnerabilities).
  - `posture/scanners/k8s_scanner.py`: CIS Kubernetes benchmarks (Pod Security Standards, privileged containers, ServiceAccount automounts, NetworkPolicies).
  - `posture/scanners/github_scanner.py`: Secret leakage scanning (AWS keys, private keys, GitHub tokens) and branch protection policies.
- Master Orchestrator: `posture/run_posture_scans.py`
- Database Architecture: ClickHouse `ReplacingMergeTree(scan_timestamp)` and analytical views `v_latest_posture` / `v_posture_summary`.
- Automated Test Suite: `tests/integration/test_posture_scanners.py`.

---

## 2. Threat Modeling & Security Analysis

| Threat / Risk Vector | Severity | Analysis & Implemented Defense | Status |
|---|---|---|---|
| **Denial of Service via Command Hang / Subprocess Stalls** | **HIGH** | Initial SSH inspections to remote VM could block on password prompts. **Mitigation:** Enforced `-o BatchMode=yes` and strict timeouts (`ConnectTimeout=3`, subprocess `timeout=5`) across all scanners to prevent thread exhaustion. | **Resolved & Verified** |
| **Command Injection in Scanners** | **HIGH** | Scanners execute system commands (`sysctl`, `kubectl`, `git`, `gh`). **Mitigation:** Zero shell interpolation (`shell=False`); commands are executed strictly as argument vectors `[prog, arg1, arg2]`. Input repository names and file paths are type-checked and sanitized. | **Verified** |
| **Data Leakage in Posture Details** | **MEDIUM** | Secret scanning flags potential exposed credentials. Storing actual secret keys in ClickHouse could create secondary credential exposure. **Mitigation:** Scanner redacts secret values, only recording rule check ID, occurrence counts, and file references without plaintext secret strings. | **Verified** |
| **Excessive Database Privileges** | **HIGH** | `siem_detector_role` and `siem_ingest_role` must not have drop or alter privileges. **Mitigation:** Verified Ingest role has only `INSERT` on `siem.posture_findings`; Detector role has read-only `SELECT` on analytical views (`v_latest_posture`, `v_posture_summary`). | **Verified** |
| **Idempotency & Finding State Flapping** | **MEDIUM** | Re-running posture scans could cause findings count explosion or duplicate active alerts. **Mitigation:** Implemented `ReplacingMergeTree(scan_timestamp)` ordered by `(asset_type, asset_id, finding_type, check_id)` ensuring subsequent scans update state in-place rather than duplicating findings. | **Verified** |

---

## 3. Verification & Live Metrics

- **Scanners Executed Successfully:**
  - `laptop` (`SUSHANKYA`): 1 finding (`CIS-HOST-2.1` SUID Process Core Dumps Enabled).
  - `vm` (`prod-linux-vm-01`): 5 findings (`CIS-VM-5.2.10`, `CIS-VM-5.2.7`, `CIS-VM-5.1.2`, `CVE-2023-4911`, `CVE-2024-1086`).
  - `k8s` (`kind-siem-k8s`): 3 findings (`CIS-K8S-5.2.5`, `CIS-K8S-5.3.2`, `CIS-K8S-5.1.5`).
  - `github` (`ShudarsanRegmi/mini-siem-clickhouse`): 2 findings (`CIS-GIT-1.0`, `CIS-GIT-2.3`).
- **Deduplication Tested:** Verified in `test_posture_ingestion_and_deduplication` that transition from `OPEN` to `RESOLVED` replaces the row in `v_latest_posture` without duplication.
- **Automated Regression Suite:** 28/28 tests passing across Unit, Integration, Security, and E2E suites.
