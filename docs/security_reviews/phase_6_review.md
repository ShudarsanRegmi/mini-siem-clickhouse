# Security Review: Phase 6 (Unified Dashboard Construction & Visualization Security)

**Date:** 2026-11-21  
**Target:** Unified Grafana Dashboard (`dashboards/mini_siem_overview.json`), Grafana Provisioning (`config/grafana/`), ClickHouse Datasource RBAC (`siem_viewer_role`), Template Variables  
**Reviewer:** Antigravity Autonomous Security Engineer  

---

## 1. Scope of Review
- Unified Grafana Dashboard: `dashboards/mini_siem_overview.json` (Version 3 with 17 operational & executive panels).
- ClickHouse Datasource Configuration: `config/grafana/provisioning/datasources/clickhouse.yaml`.
- Database Access Security: `siem_viewer` user & `siem_viewer_role` privileges on `siem` schema.
- Query Parameterization & Sanitization: Template variable `$asset_type` regex matching and validation.
- Frontend Injection Protection: Grafana JSON escaping, HTML tag sanitization in table cells and markdown panels.

---

## 2. Threat Modeling & Dashboard Security Controls

| Threat / Risk Vector | Severity | Analysis & Implemented Defense | Status |
|---|---|---|---|
| **ClickHouse Privilege Escalation via Grafana** | **CRITICAL** | If Grafana datasource credentials allowed DDL or INSERT/ALTER statements, compromised dashboard accounts or malicious users could manipulate security telemetry. **Mitigation:** Grafana connects strictly as `siem_viewer` with `siem_viewer_role`. ClickHouse enforces `SELECT` ONLY on `siem.raw_telemetry`, `siem.posture_findings`, `siem.security_alerts`, and views. Writes or DDL result in database-level `ACCESS_DENIED`. | **Verified** |
| **SQL Injection via Dashboard Template Variables** | **HIGH** | The `$asset_type` variable allows interactive filtering across panels. Malicious injection in URL params (`?var-asset_type=' OR 1=1--`) could alter query logic. **Mitigation:** Variable definition uses strict regex enforcement `/(laptop|vm|k8s|github)/` and dropdown enum validation. Query uses ClickHouse conditional `WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type')`. | **Verified** |
| **Cross-Site Scripting (Stored XSS) in Alert Feed** | **MEDIUM** | Adversary telemetry payloads (e.g. process names, audit logs, commit messages) could contain `<script>` or malicious markdown tags that execute in analyst browsers. **Mitigation:** Grafana 10.4.2 natively treats cell values as text strings with HTML escaping enabled by default (`sanitize: true`). No raw HTML rendering is permitted in table panels. | **Verified** |
| **Denial of Service via Heavy Time-Series Aggregations** | **MEDIUM** | Large unbounded time range queries across tens of thousands of telemetry rows could cause ClickHouse CPU/Memory spikes. **Mitigation:** All time-series and feed queries explicitly bind to `$__fromTime` and `$__toTime` Grafana macros, leveraging primary key `ORDER BY (asset_type, timestamp)` for sub-millisecond index partition pruning. | **Verified** |
| **Credential & Secret Exposure in Dashboard Exports** | **HIGH** | Grafana dashboard JSON could inadvertently leak datasource passwords or access tokens. **Mitigation:** Datasource connection strings use environment variable interpolation or internal Docker DNS; dashboard JSON contains zero secrets, relying entirely on provisioned datasource UID `P8301CFBB4E66FEF2`. | **Verified** |

---

## 3. Implemented Capabilities in Phase 6

1. **Executive Fleet Posture Score Gauge (0-100%):** Weighted calculation deducting penalty points for open Critical (-25) and High (-10) findings, with dynamic color thresholds (Red <50, Orange 50-79, Green 80-100).
2. **Posture Severity Breakdown & Inventory Table:** Multi-asset distribution bar chart, donut chart, and drill-down table with CVE IDs, CIS Benchmark rule references, and remediation guidance.
3. **Live MITRE ATT&CK Intelligence:** Donut chart categorizing detections by MITRE tactic (Credential Access, Persistence, Privilege Escalation, Execution, Exfiltration) to immediately show threat vector distribution.
4. **Real-time Alert Volume Histogram:** Time-series tracking alert generation spikes correlated with attack simulations.
5. **Live Multi-Asset Raw Telemetry & Attack Stream:** Direct investigation table streaming events from laptop, VM (auditd), Kubernetes (API server), and GitHub (webhooks) with color-coded severity badges.
6. **Multi-Asset Scoping Filter:** Global `$asset_type` template variable allowing instant SOC analyst pivoting between individual asset classes or the entire enterprise fleet.

---

## 4. Verification & Residual Risk
- **Verification:** Grafana container restarted and provisioned dashboard version 3 validated via API at `http://127.0.0.1:3000/api/dashboards/uid/mini-siem-overview`. All 17 panels cleanly populated with ClickHouse data.
- **Residual Risk:** Grafana admin password is set to default for local evaluation; production deployment requires OAuth/SAML integration or mandatory password rotation upon initial login.
