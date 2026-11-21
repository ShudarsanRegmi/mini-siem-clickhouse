# Security Review: Phase 5 (Detection Engine & False Positive Tuning)

**Date:** 2026-11-21  
**Target:** Detection Engine (`detections/engine.py`), 5 SQL Detection Rules (`detections/rules/`), Alert Storage (`siem.security_alerts`)  
**Reviewer:** Antigravity Autonomous Security Engineer  

---

## 1. Scope of Review
- Core Engine: `detections/engine.py` (Rule evaluation, batching, state tracking, alert generation).
- SQL Detection Rules:
  - `detections/rules/sec_vm_001_cred_dump.py`: Credential Access (/etc/shadow dumping, T1003).
  - `detections/rules/sec_vm_002_cron_persistence.py`: Persistence via cron & reverse shell sockets (T1053.003, T1059.004).
  - `detections/rules/sec_k8s_001_privileged_pod.py`: Kubernetes Privileged container launch & host root escape (T1610, T1611).
  - `detections/rules/sec_k8s_002_suspicious_exec.py`: Kubernetes interactive pod exec & ServiceAccount token snooping (T1059, T1552.007).
  - `detections/rules/sec_git_001_secret_leak.py`: GitHub committed API tokens & high-entropy AWS credentials (T1552.001).
- Automated Tests: `tests/integration/test_detection_engine.py`.

---

## 2. Threat Modeling & Detection Engineering Hardening

| Threat / Risk Vector | Severity | Analysis & Implemented Defense | Status |
|---|---|---|---|
| **SQL Injection in Detection Queries** | **HIGH** | Detection queries execute dynamic SQL against ClickHouse. **Mitigation:** Time boundaries are generated strictly as structured ISO/strftime strings (`%Y-%m-%d %H:%M:%S`). Zero raw user input is concatenated into rule definitions. | **Verified** |
| **Excessive Database Permissions** | **HIGH** | Engine must not be able to delete telemetry or alter database schemas. **Mitigation:** Engine authenticates strictly using `siem_detector_role` (`SELECT` on `raw_telemetry` and `posture_findings`, `SELECT/INSERT` on `security_alerts`). Verified ingest and detector roles cannot execute DDL. | **Verified** |
| **Alert Fatigue & Resource Exhaustion (DoS)** | **HIGH** | Repeated polling over attack windows could create infinite alert storms. **Mitigation:** Implemented event fingerprinting (`rule_id::asset_id::actor::latest_timestamp`) stored in state file (`.detection_state.json`). Multiple related events are grouped into a single alert with `matched_events_count` and forensic sample evidence. | **Verified** |
| **High False Positive Rates** | **MEDIUM** | Naive string matching triggers on system log rotation and PAM logins. **Mitigation:** Authored explicit exclusion clauses: PAM daemons (`login`, `sshd`, `systemd-userwork`), system logrotate (`/usr/sbin/logrotate`), and core CNI daemonsets (`kube-proxy`, `daemon-set-controller` in `kube-system`). Verified via `test_false_positive_tuning_cron_logrotate`. | **Verified** |
| **Credential Exposure in Evidence Context** | **MEDIUM** | Alerts record command-line evidence. **Mitigation:** Secret values in evidence context are truncated and path-scoped; raw credentials are sanitized prior to database storage. | **Verified** |

---

## 3. Verification & Live Metrics

- **Detection Engine Execution:** Evaluated 5 rules across real telemetry generated during Phase 4 simulations.
- **Alerts Generated in ClickHouse (`siem.security_alerts`):**
  - `SEC-VM-001` (Credential Access): Triggered on `/etc/shadow` access.
  - `SEC-VM-002` (Cron Persistence): Triggered on `/etc/cron.d/sync_backdoor`.
  - `SEC-K8S-001` (Privileged Pod): Triggered on `default/pods/privileged-escape-pod`.
  - `SEC-K8S-002` (Pod Exec): Triggered on `kubectl exec` into `victim-target-app`.
  - `SEC-GIT-001` (Secret Leak): Triggered on AWS key commit webhook.
- **Deduplication Verification:** Running a secondary evaluation cycle immediately yielded `0 new alerts`, proving idempotent alert suppression.
- **Automated Regression Suite:** 32/32 tests passing across Unit, Integration, Security, and E2E tiers.
