-- ==============================================================================
-- Mini SIEM: ClickHouse DDL & RBAC Roles Initializer
-- Database: siem
-- Security Note: Roles are defined here. Users with credentials are created
-- dynamically from .env by scripts/init_db.py to avoid hardcoded secrets.
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS siem;

-- ------------------------------------------------------------------------------
-- 1. Table: raw_telemetry
-- Ingests high-throughput event logs, audit records, and process telemetry.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem.raw_telemetry
(
    timestamp DateTime64(3, 'UTC') DEFAULT now64(3),
    asset_type Enum8('laptop' = 1, 'vm' = 2, 'k8s' = 3, 'github' = 4),
    asset_id String,
    event_category LowCardinality(String),
    event_type LowCardinality(String),
    severity LowCardinality(String) DEFAULT 'INFO',
    actor String DEFAULT '',
    source_ip Nullable(String),
    process_name Nullable(String),
    command_line Nullable(String),
    target_resource Nullable(String),
    raw_json String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asset_type, asset_id, event_category, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- ------------------------------------------------------------------------------
-- 2. Table: posture_findings
-- Ingests vulnerability (CVEs) and misconfiguration (CIS benchmarks) scan results.
-- Uses ReplacingMergeTree so updated scan runs deduplicate earlier finding keys.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem.posture_findings
(
    finding_id UUID DEFAULT generateUUIDv4(),
    scan_timestamp DateTime64(3, 'UTC') DEFAULT now64(3),
    asset_type Enum8('laptop' = 1, 'vm' = 2, 'k8s' = 3, 'github' = 4),
    asset_id String,
    scanner_tool LowCardinality(String),
    finding_type Enum8('vulnerability' = 1, 'misconfiguration' = 2, 'secret_leak' = 3),
    check_id String,
    title String,
    severity Enum8('CRITICAL' = 1, 'HIGH' = 2, 'MEDIUM' = 3, 'LOW' = 4, 'INFO' = 5),
    status Enum8('OPEN' = 1, 'RESOLVED' = 2, 'SUPPRESSED' = 3) DEFAULT 'OPEN',
    remediation String DEFAULT '',
    details String DEFAULT ''
)
ENGINE = ReplacingMergeTree(scan_timestamp)
ORDER BY (asset_type, asset_id, check_id);

-- ------------------------------------------------------------------------------
-- 3. Table: security_alerts
-- Stores triggered detection rules, MITRE ATT&CK mapping, and forensic context.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem.security_alerts
(
    alert_id UUID DEFAULT generateUUIDv4(),
    triggered_at DateTime64(3, 'UTC') DEFAULT now64(3),
    rule_id String,
    rule_name String,
    mitre_tactic LowCardinality(String),
    mitre_technique LowCardinality(String),
    asset_type Enum8('laptop' = 1, 'vm' = 2, 'k8s' = 3, 'github' = 4),
    asset_id String,
    severity Enum8('CRITICAL' = 1, 'HIGH' = 2, 'MEDIUM' = 3, 'LOW' = 4),
    matched_events_count UInt32 DEFAULT 1,
    alert_description String,
    evidence_context String DEFAULT '{}',
    false_positive_tuning_notes String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(triggered_at)
ORDER BY (severity, triggered_at, rule_id);

-- ------------------------------------------------------------------------------
-- 4. Analytical Views for Reporting & Dashboards
-- ------------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS siem.v_latest_posture AS
SELECT * FROM siem.posture_findings FINAL;

CREATE VIEW IF NOT EXISTS siem.v_posture_summary AS
SELECT
    asset_type,
    asset_id,
    countIf(severity = 'CRITICAL' AND status = 'OPEN') AS critical_count,
    countIf(severity = 'HIGH' AND status = 'OPEN') AS high_count,
    countIf(severity = 'MEDIUM' AND status = 'OPEN') AS medium_count,
    countIf(severity = 'LOW' AND status = 'OPEN') AS low_count,
    countIf(status = 'OPEN') AS total_open_findings,
    max(scan_timestamp) AS last_scanned_at
FROM siem.v_latest_posture
GROUP BY asset_type, asset_id;

-- ------------------------------------------------------------------------------
-- 5. RBAC Roles Definition (Least Privilege)
-- ------------------------------------------------------------------------------
-- Ingest Role: INSERT only on telemetry and posture tables
CREATE ROLE IF NOT EXISTS siem_ingest_role;
GRANT INSERT ON siem.raw_telemetry TO siem_ingest_role;
GRANT INSERT ON siem.posture_findings TO siem_ingest_role;

-- Detector Role: SELECT on telemetry and posture and INSERT on alerts
CREATE ROLE IF NOT EXISTS siem_detector_role;
GRANT SELECT ON siem.raw_telemetry TO siem_detector_role;
GRANT SELECT ON siem.posture_findings TO siem_detector_role;
GRANT INSERT ON siem.security_alerts TO siem_detector_role;

-- Viewer Role (e.g. Grafana): Read-only SELECT on all siem tables and views
CREATE ROLE IF NOT EXISTS siem_viewer_role;
GRANT SELECT ON siem.* TO siem_viewer_role;
