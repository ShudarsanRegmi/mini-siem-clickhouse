# Mini SIEM on ClickHouse

A high-performance, lightweight Security Information and Event Management (SIEM) and Security Posture Management engine powered by **ClickHouse**.

## Highlights & Capabilities
- **Multi-Asset Telemetry**: Ingests audit, process, and security logs from 4 distinct asset classes:
  1. **Host / Laptop**: Process execution, system logs, local filesystem vulnerability scans.
  2. **Linux VM**: Auditd telemetry, privilege escalation logs, Linux hardening scans.
  3. **Kubernetes Cluster**: API server audit logs, runtime pod execution, CIS benchmarks via `kube-bench` and `trivy`.
  4. **GitHub Repositories**: Commit activity, secret scanning (`gitleaks`), webhook events, and branch security policies.
- **Unified ClickHouse Data Model**:
  - `siem.raw_telemetry`: High-throughput time-series event log (`MergeTree`).
  - `siem.posture_findings`: Current posture state & deduplicated findings (`ReplacingMergeTree`).
  - `siem.security_alerts`: Fired detection alerts, MITRE ATT&CK mapping, and triage evidence (`MergeTree`).
- **Detection Engineering**:
  - Scheduled SQL-based correlation and detection rules catching 5 realistic attack scenarios.
  - Granular false-positive tuning and noise suppression.
- **Single-Pane-of-Glass Dashboard**:
  - Grafana dashboard providing fleet posture scoring, open findings by severity, and real-time alert timelines.

## Quick Start
```bash
# 1. Spin up ClickHouse and Grafana
docker compose up -d

# 2. Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Initialize Kind Kubernetes Cluster with Audit Logging
./scripts/setup_k8s.sh

# 4. Trigger Posture Scans
python posture/run_posture_scans.py

# 5. Start Detection Engine
python detections/engine.py
```
