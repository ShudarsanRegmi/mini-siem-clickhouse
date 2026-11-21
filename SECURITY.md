# Security Policy & Architecture

## Security-by-Default Core Principles

This platform functions as a Security Information and Event Management (SIEM) and Security Posture platform. Because it aggregates and monitors critical infrastructure telemetry, the platform itself must adhere to rigorous security standards.

### 1. Principle of Least Privilege & RBAC
Access to ClickHouse is segregated using dedicated database roles and service users:
- **`siem_ingest`**: Granted strictly `INSERT` permissions on `siem.raw_telemetry` and `siem.posture_findings`. It cannot read existing logs, modify alerts, or drop tables.
- **`siem_detector`**: Granted `SELECT` on `siem.raw_telemetry` and `INSERT` on `siem.security_alerts`. It cannot mutate raw telemetry or alter posture state.
- **`siem_grafana`**: Granted strictly `SELECT` permissions across `siem.*`. It cannot perform any write, update, or administrative operations.
- **`default` (Admin)**: Used strictly for initialization and schema migrations.

### 2. Defense in Depth & Zero Trust Ingestion
- **Cryptographic Authentication**: GitHub Webhook payloads must be verified using HMAC-SHA256 (`X-Hub-Signature-256`) against `GITHUB_WEBHOOK_SECRET` before parsing.
- **Bearer Token Enforcement**: Custom ingestion endpoints require an `Authorization: Bearer <token>` header matching `INGESTION_BEARER_TOKEN`.
- **Strict Input Validation**: All ingestion payloads are parsed using Pydantic models with strict typing, length constraints, and schema validation before any database insertion.
- **SQL Injection Prevention**: Detection queries and data ingestion utilize parameterized queries and native binary protocols (`clickhouse-connect`) rather than unsanitized raw string interpolation.

### 3. Fail-Secure Behavior & Error Masking
- Authentication or signature failures immediately return HTTP `401 Unauthorized` or `403 Forbidden` without processing or logging the payload.
- Error responses return opaque, safe messages; internal tracebacks, database schema details, or server banners are never leaked in public API responses.
- Application logs are sanitized to prevent credential exposure (e.g. passwords, bearer tokens, or private keys are masked before logging).

### 4. Secret Management
- Secrets and credentials must never be committed to source control.
- All secrets are injected at runtime via environment variables loaded from `.env`.
- `.gitignore` explicitly prevents accidental leakage of `.env`, private keys (`.pem`, `.key`, `id_rsa*`), certificates, kubeconfig files, and data volumes.
- `.env.example` provides a documented template with secure defaults.

### 5. Continuous Post-Implementation Security Reviews
Every implemented feature undergoes a mandatory security review assessing:
- Insecure configurations or unnecessary exposed ports.
- Excessive privileges or broken access control.
- Unvalidated inputs or SQL injection vectors.
- Sensitive data leakage in telemetry, logs, or error responses.
