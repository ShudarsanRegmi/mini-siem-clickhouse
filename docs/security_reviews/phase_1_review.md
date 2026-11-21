# Security Review: Phase 1 (ClickHouse Core Infrastructure & Ingestion Gateway)

**Date:** 2026-11-21  
**Target:** ClickHouse Schema, RBAC Model, Docker Compose Hardening, and Ingestion Gateway  
**Reviewer:** Antigravity Autonomous Security Engineer  

---

## 1. Scope of Review
- Infrastructure: `docker-compose.yml` (ClickHouse and Grafana configuration)
- Database Security: `config/clickhouse/init.sql` and `scripts/init_db.py`
- Gateway Security: `src/ingestion/collector.py`
- RBAC Enforcement: `tests/test_clickhouse_security.py`
- Authentication & Validation: `tests/test_ingestion_security.py`

---

## 2. Security Findings & Risk Analysis

| Component | Vector / Potential Threat | Mitigation & Verification | Status |
|---|---|---|---|
| **ClickHouse Network Exposure** | Public exposure of HTTP (8123) and Native (9000) ports allowing unauthorized remote network scanning. | Ports explicitly bound to `127.0.0.1` (`127.0.0.1:8123:8123`). Containers communicate on isolated Docker bridge network `siem_net`. | **Verified** |
| **Database Overprivilege** | Service compromised leading to table deletion, log alteration, or arbitrary query execution. | Enforced 3 distinct RBAC roles (`siem_ingest_role`: INSERT only; `siem_detector_role`: SELECT on telemetry/posture and INSERT on alerts; `siem_viewer_role`: SELECT only). Probed via `test_clickhouse_security.py` — unauthorized actions fail with `ACCESS_DENIED`. | **Verified** |
| **Secret Leakage in Git** | Database passwords or API tokens hardcoded in configuration or SQL files. | All credentials sourced via environment variables (`.env`). `.env` is explicitly gitignored and verified via `git status`. Zero hardcoded secrets in `init.sql` or `docker-compose.yml`. | **Verified** |
| **Unauthenticated Ingestion** | Attacker floods telemetry table with bogus events or unauthorized data. | Endpoints protected via Bearer Token authentication (`Authorization: Bearer <token>`). Unauthenticated requests rejected with HTTP 401; invalid tokens rejected with HTTP 403. | **Verified** |
| **Webhook Forgery (GitHub)** | Attacker sends malicious HTTP POST simulating GitHub events to tamper with audit state. | Mandatory HMAC-SHA256 signature verification (`X-Hub-Signature-256`) against pre-shared secret. Payloads with forged or missing signatures fail fast (HTTP 401). | **Verified** |
| **Denial of Service (DoS)** | Attacker sends gigabyte-sized JSON arrays exhausting server memory. | Strict Pydantic model validation and payload batch size limit enforced (max 5,000 events per request, returns HTTP 413). | **Verified** |
| **Grafana Attack Surface** | Anonymous access or tracking beacons enabled by default. | Anonymous access disabled (`GF_AUTH_ANONYMOUS_ENABLED=false`). Analytics reporting and version check beacons disabled. Read-only ClickHouse user provisioned. | **Verified** |

---

## 3. Automated Verification Results
- `tests/test_clickhouse_security.py`: 4/4 passing (Admin, Ingest, Detector, Viewer permissions).
- `tests/test_ingestion_security.py`: 7/7 passing (Authentication, HMAC verification, Batch validation).
- Automated test script `scripts/verify_phase1.sh` exited with status `0`.
