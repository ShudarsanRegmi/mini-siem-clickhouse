# Mini SIEM Architecture & Data Flow

## 1. System Components

```mermaid
graph TB
    subgraph Assets ["Monitored Assets"]
        Host["Host / Laptop<br/>(Process / OS logs)"]
        VM["Linux VM (Container/Host)<br/>(Auditd / Syslog)"]
        K8s["Kubernetes Cluster (Kind)<br/>(API Audit Logs / Workloads)"]
        GitHub["GitHub Repositories<br/>(Webhooks / Audit API)"]
    end

    subgraph Pipeline ["Collection & Normalization"]
        VectorCollector["Vector / Forwarders<br/>(JSON Normalization)"]
        PostureCollector["Posture Scan Engine<br/>(Trivy / Lynis / Gitleaks)"]
    end

    subgraph ClickHouse ["ClickHouse OLAP Storage"]
        RawTel["siem.raw_telemetry<br/>(MergeTree)"]
        PostureFindings["siem.posture_findings<br/>(ReplacingMergeTree)"]
        SecAlerts["siem.security_alerts<br/>(MergeTree)"]
    end

    subgraph Analytics ["Detection & Presentation"]
        DetEngine["Detection Engine<br/>(Scheduled SQL Correlation)"]
        Grafana["Grafana Dashboard<br/>(ClickHouse Plugin)"]
    end

    Host & VM & K8s & GitHub --> VectorCollector
    Host & VM & K8s & GitHub --> PostureCollector

    VectorCollector --> RawTel
    PostureCollector --> PostureFindings

    RawTel --> DetEngine
    DetEngine --> SecAlerts

    RawTel & PostureFindings & SecAlerts --> Grafana
```

## 2. Ingestion Strategy

1. **High-Throughput Raw Telemetry**:
   - Normalized into `asset_type`, `asset_id`, `event_category`, `event_type`, `actor`, `source_ip`, `process_name`, `command_line`, `target_resource`, and `raw_json`.
   - Indexed and partitioned by month for rapid analytical filtering.

2. **Deduplicated Posture State**:
   - `ReplacingMergeTree` keyed on `(asset_type, asset_id, check_id)` ensures that subsequent scans update findings without accumulating stale duplicates.

3. **Detection Engine**:
   - Runs deterministic, explainable SQL queries against `raw_telemetry`.
   - Populates `security_alerts` with MITRE ATT&CK metadata and forensic context.
