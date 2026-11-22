# Mini SIEM Telemetry & Collected Events Catalog

This reference catalog documents all security and operational events collected across the four monitored asset classes in the **ClickHouse Mini SIEM** infrastructure.

---

## 1. Multi-Asset Telemetry Architecture

Every event collected from the four asset classes is normalized into a standard event schema and ingested via the FastAPI Ingestion Gateway into the ClickHouse `siem.raw_telemetry` table.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               TELEMETRY COLLECTION PIPELINE                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  [Asset 1: Laptop]           [Asset 2: Real VM]         [Asset 3: Kubernetes]       [Asset 4: GitHub]
  assets/laptop/collector.py  assets/vm/collector.py     assets/k8s/collector.py     assets/github/collector.py
  (Processes & Auth)          (auditd & syslog)          (API Server Audit Log)      (Webhooks & API)
          │                           │                           │                         │
          └───────────────────────────┴─────────────┬─────────────┴─────────────────────────┘
                                                    │
                                                    ▼ [HTTP POST /api/v1/telemetry]
                                    FastAPI Ingestion Gateway (Port 8000)
                                                    │
                                                    ▼ [SQL INSERT]
                                      ClickHouse: siem.raw_telemetry
                                                    │
                                                    ├──────────────────────────┐
                                                    ▼                          ▼
                                          Detection Engine               Grafana Dashboards
                                         (Evaluates 5 Rules)             (Ports 3000)
                                                    │
                                                    ▼
                                      ClickHouse: siem.security_alerts
```

---

## 2. Ingested Events Catalog by Asset Class

### Asset 1: Laptop Workstation Telemetry
- **Asset ID**: Hostname (e.g. `SUSHANKYA`)
- **Collector**: `assets/laptop/collector.py`
- **Mechanism**: Local Linux process accounting (`ps`) and login session monitoring (`who`) with regex-based credential and secret redaction.

| Event Category | Event Type | Severity | Description | Key Extracted Fields |
|---|---|---|---|---|
| `process` | `process_snapshot` | `INFO` / `LOW` | Periodic full inventory of active processes running across the operating system. | `process_name`, `command_line`, `actor` (user), PID, args *(passwords automatically redacted)* |
| `process` | `process_spawn` | `INFO` | Real-time process spawn and execution events. | `process_name`, `command_line`, `actor`, timestamp |
| `auth` | `active_session` | `INFO` | Active user login sessions and terminal allocations (via `who`). | `actor` (username), `target_resource` (TTY/display `:0`, `pts/0`), login timestamp |
| `rbac_audit` | `probe` | `INFO` | Security evaluation and permissions audit probes. | `actor`, `process_name`, test metadata |

---

### Asset 2: Real Linux VM (VMware Workstation Debian 12)
- **Asset ID**: `debianvm` (IP: `172.16.151.134`)
- **Collector**: `assets/vm/collector.py`
- **Mechanism**: Remote SSH streaming and ingestion of Linux kernel auditd logs (`/var/log/audit/audit.log`) and system authentication logs (`/var/log/auth.log`).

| Event Category | Event Type | Severity | Description | Attack Scenario Relevance |
|---|---|---|---|---|
| `auditd` / `auth` | `sensitive_file_read` / `sensitive_file_access` | `CRITICAL` / `HIGH` | Linux auditd watch rule triggered when a process attempts to open or read `/etc/shadow`, `/etc/passwd`, or `/etc/sudoers`. | **Attack Scenario 1**: Credential Access via `/etc/shadow` dumping (MITRE T1003.008) |
| `auditd` | `cron_modification` | `HIGH` | File integrity monitoring alert triggered when cron files (`/etc/cron.d/sync_backdoor`, `/etc/crontab`) are created or modified. | **Attack Scenario 2**: Persistence via scheduled cron backdoor (MITRE T1053.003) |
| `auditd` | `auditd_syscall` | `LOW` | Monitored Linux system calls (`execve`, `openat`, `socket`, `connect`) triggered by high-risk binaries. | System call forensic tracking |
| `auth` | `ssh_login_success` | `INFO` | Inbound SSH authentications, public-key vs password authentication methods, remote client IP. | Remote access and lateral movement tracking |
| `auth` | `auth_event` | `INFO` | General PAM authentication sessions, session open/close events from `/var/log/auth.log`. | Authentication session monitoring |
| `privilege` | `sudo_command` | `LOW` | Commands executed with elevated privileges via `sudo`. | Privilege escalation monitoring |
| `process` | `cron_job_executed` | `INFO` | System cron daemon executing scheduled system or user tasks. | Baseline scheduled task monitoring |
| `network` | `outbound_connection` | `INFO` | Outbound network socket creation and package manager connections. | C2 egress & reverse shell monitoring |

---

### Asset 3: Kubernetes Infrastructure (Kind Cluster v1.31.2)
- **Asset ID**: `kind-siem-k8s`
- **Collector**: `assets/k8s/collector.py`
- **Mechanism**: Real-time parsing of Kubernetes API Server Audit Logs (`.audit/kube-audit.log`) captured at `RequestResponse` logging depth.

| Event Category | Event Type | Severity | Description | Attack Scenario Relevance |
|---|---|---|---|---|
| `k8s_audit` | `create_pods_exec` (`pods/exec`) | `HIGH` | An interactive shell or command execution inside a pod via `kubectl exec`. | **Attack Scenario 4**: Interactive container hijacking & ServiceAccount token harvesting (MITRE T1059, T1552.007) |
| `k8s_audit` | `create_pods` (Privileged Pod) | `CRITICAL` | Pod creation requests containing `securityContext.privileged: true` or `hostPath: /`. | **Attack Scenario 3**: Container escape to host root filesystem (MITRE T1610, T1611) |
| `k8s_audit` | `get_secrets` / `create_secrets` / `delete_secrets` | `MEDIUM` / `INFO` | Direct requests to inspect, extract, or delete Kubernetes Secrets. | Credential discovery and secret harvesting |
| `k8s_audit` | `create_clusterroles` / `create_rolebindings` | `MEDIUM` | Modifications to cluster RBAC permissions and privileges. | Privilege escalation and unauthorized role granting |
| `k8s_audit` | `get_pods` / `watch_pods` / `list_pods` | `INFO` | Workload discovery and operational status polling. | Discovery (MITRE T1082) & routine controller health checks |
| `k8s_audit` | `update_leases` / `get_endpoints` | `INFO` | Internal Kubernetes control plane coordination (leader election, endpoint leasing). | Operational cluster telemetry |

---

### Asset 4: GitHub Source Repository (`ShudarsanRegmi/mini-siem-clickhouse`)
- **Asset ID**: `ShudarsanRegmi/mini-siem-clickhouse`
- **Collector**: `assets/github/collector.py`
- **Mechanism**: Authenticated HMAC-SHA256 signed GitHub webhooks received by the Ingestion Gateway and periodic commit polling via GitHub REST API.

| Event Category | Event Type | Severity | Description | Attack Scenario Relevance |
|---|---|---|---|---|
| `github_audit` | `git_push_push_secret_leak` | `CRITICAL` | Git push commit containing high-entropy AWS access keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), or private keys. | **Attack Scenario 5**: Committed credential canary exposure (MITRE T1552.001) |
| `github_audit` | `git_push_push` | `INFO` | Routine git push commits to branch heads, tracking committer name, email, commit messages, and modified files. | Source code integrity and change auditing |
| `github_audit` | `git_pull_request_opened` / `closed` | `INFO` | Pull request lifecycle events, code review activity, and branch merge tracking. | Branch protection and code governance tracking |

---

## 3. Normalized ClickHouse Schema (`siem.raw_telemetry`)

Every telemetry event across all asset classes is stored in ClickHouse using the following schema:

```sql
CREATE TABLE IF NOT EXISTS siem.raw_telemetry
(
    timestamp       DateTime64(3, 'UTC') DEFAULT now64(3),
    asset_type      Enum8('laptop' = 1, 'vm' = 2, 'k8s' = 3, 'github' = 4),
    asset_id        String,
    event_category  LowCardinality(String),
    event_type      LowCardinality(String),
    severity        LowCardinality(String) DEFAULT 'INFO',
    actor           String DEFAULT '',
    source_ip       Nullable(String),
    process_name    Nullable(String),
    command_line    Nullable(String),
    target_resource Nullable(String),
    raw_json        String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asset_type, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;
```

---

## 4. Telemetry-to-Detection Rule Mapping

| Attack Scenario | Trigger Telemetry Event | Detection Rule ID | Rule Name | MITRE ATT&CK Tactic |
|---|---|---|---|---|
| **Scenario 1 (VM)** | `sensitive_file_read` / `/etc/shadow` | `SEC-VM-001` | Unauthorized `/etc/shadow` Access | Credential Access (TA0006) |
| **Scenario 2 (VM)** | `cron_modification` / `/dev/tcp/` socket | `SEC-VM-002` | Cron Modification / Reverse Shell | Persistence (TA0003) |
| **Scenario 3 (K8s)** | `create_pods` (`privileged: true`) | `SEC-K8S-001` | Privileged Container Escape | Privilege Escalation (TA0004) |
| **Scenario 4 (K8s)** | `create_pods_exec` (`pods/exec`) | `SEC-K8S-002` | Interactive Pod Exec & Token Snooping | Execution (TA0002) |
| **Scenario 5 (Git)** | `git_push_push_secret_leak` (`AKIA...`) | `SEC-GIT-001` | Committed Secret / AWS Key Canary | Credential Exposure (TA0010) |

---

## 5. Quick Verification Queries

### Event Count by Asset and Category
```sql
SELECT 
    asset_type,
    event_category,
    event_type,
    count() AS total_events,
    groupUniqArray(severity) AS severities
FROM siem.raw_telemetry
GROUP BY asset_type, event_category, event_type
ORDER BY asset_type, total_events DESC
FORMAT PrettyCompact;
```

### Inspect High-Risk Events (CRITICAL & HIGH)
```sql
SELECT 
    timestamp,
    asset_type,
    event_type,
    actor,
    target_resource,
    command_line
FROM siem.raw_telemetry
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY timestamp DESC
LIMIT 10
FORMAT PrettyCompact;
```
