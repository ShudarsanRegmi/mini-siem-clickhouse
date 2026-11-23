# Security Posture Assessment: `posture_findings` Entity, Scanners & Dashboard Integration

This guide provides a comprehensive breakdown of the **`posture_findings`** dataset in the Mini SIEM: what it represents, how the four automated scanners audit your infrastructure, how ClickHouse manages state deduplication, and which Grafana dashboard components depend on it.

---

## 1. Posture vs. Telemetry: The Fundamental Distinction

In enterprise security engineering, data is split into two complementary worlds:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ENTERPRISE SECURITY DATA                                 │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ 1. RUNTIME TELEMETRY & DETECTIONS         │ 2. SECURITY POSTURE ASSESSMENT             │
│ (Dynamic / Streaming / Event-Based)       │ (Static / State-Based / Attack Surface)    │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ • "What is happening right now?"          │ • "How secure is our configuration right   │
│ • Millions of events per day              │   now, before an attacker arrives?"        │
│ • Process executions, auditd syscalls,    │ • Software vulnerabilities (CVEs),         │
│   SSH logins, git pushes, pod execs       │   CIS benchmark misconfigurations, secrets │
│ • Table: siem.raw_telemetry               │ • Table: siem.posture_findings             │
│ • Alerts: siem.security_alerts            │ • Views: v_latest_posture, v_posture_sum   │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

**Security Posture** answers the question: *Where are our weaknesses?*  
If you leave `/etc/shadow` world-readable or allow `privileged: true` on pods, you have poor posture. When an attacker actually exploits that weakness, runtime telemetry captures the event and fires an alert.

---

## 2. The `posture_findings` Entity & ClickHouse Schema

Every vulnerability and CIS benchmark scan records into `siem.posture_findings`.

### The DDL Schema:
```sql
CREATE TABLE IF NOT EXISTS siem.posture_findings
(
    finding_id      UUID DEFAULT generateUUIDv4(),
    scan_timestamp  DateTime64(3, 'UTC') DEFAULT now64(3),
    asset_type      Enum8('laptop' = 1, 'vm' = 2, 'k8s' = 3, 'github' = 4),
    asset_id        String,
    scanner_tool    LowCardinality(String),
    finding_type    Enum8('vulnerability' = 1, 'misconfiguration' = 2, 'secret_leak' = 3),
    check_id        String,
    title           String,
    severity        Enum8('CRITICAL' = 1, 'HIGH' = 2, 'MEDIUM' = 3, 'LOW' = 4, 'INFO' = 5),
    status          Enum8('OPEN' = 1, 'RESOLVED' = 2, 'SUPPRESSED' = 3) DEFAULT 'OPEN',
    remediation     String DEFAULT '',
    details         String DEFAULT ''
)
ENGINE = ReplacingMergeTree(scan_timestamp)
PRIMARY KEY (asset_type, asset_id, finding_type, check_id)
ORDER BY (asset_type, asset_id, finding_type, check_id);
```

### Data Fields Explained:
- **`finding_id`**: Unique UUID identifying this specific scan result.
- **`asset_type` & `asset_id`**: Which machine or service was scanned (`laptop:SUSHANKYA`, `vm:prod-linux-vm-01`, `k8s:kind-siem-k8s`, `github:ShudarsanRegmi/mini-siem-clickhouse`).
- **`scanner_tool`**: The audit engine (`host-cis-auditor`, `vm-cis-auditor`, `k8s-cis-auditor`, `github-security-auditor`).
- **`finding_type`**:
  - `vulnerability`: A known software flaw with an assigned CVE ID (e.g. `CVE-2024-1086`).
  - `misconfiguration`: A deviation from industry hardening standards (CIS Benchmarks).
  - `secret_leak`: Statically discovered credentials or canary tokens.
- **`check_id`**: Canonical rule or vulnerability identifier (`CIS-VM-5.2.10`, `CVE-2023-4911`, `CIS-K8S-5.2.5`).
- **`status`**: `OPEN` (active issue), `RESOLVED` (patched/remediated), or `SUPPRESSED` (accepted business risk).
- **`remediation`**: Concrete, copy-pasteable CLI command or instructions to fix the issue.

---

### Why `ReplacingMergeTree` is Essential for Posture

In a traditional relational database (PostgreSQL), when you fix a vulnerability, you run:
`UPDATE posture_findings SET status = 'RESOLVED' WHERE check_id = 'CIS-VM-5.2.10';`

**However, ClickHouse is an append-only analytical database.** It does not perform in-place updates.  
To handle state changes efficiently, ClickHouse provides **`ReplacingMergeTree(scan_timestamp)`**:
1. When the scanner runs at 10:00 AM, it inserts `check_id = 'CIS-VM-5.2.10'`, `status = 'OPEN'`.
2. The sysadmin fixes the configuration.
3. The scanner runs at 11:00 AM, sees the issue is gone, and inserts the same `check_id = 'CIS-VM-5.2.10'` with `status = 'RESOLVED'`.
4. ClickHouse matches the primary key `(asset_type, asset_id, finding_type, check_id)`. The newer record (`scan_timestamp = 11:00 AM`) automatically supersedes the older one!

#### The Views:
- **`siem.v_latest_posture`**: Queries `siem.posture_findings FINAL`, performing on-the-fly deduplication so you only see the latest state of each check.
- **`siem.v_posture_summary`**: Aggregates open criticals, highs, and mediums per asset for executive rollups.

---

## 3. How the 4 Automated Posture Scanners Work

The posture assessment suite is orchestrated by `posture/run_posture_scans.py` and executed across all 4 asset classes:

```
                                  posture/run_posture_scans.py
                                                │
         ┌───────────────────────┬──────────────┴──────────────┬────────────────────────┐
         ▼                       ▼                             ▼                        ▼
┌──────────────────┐    ┌──────────────────┐          ┌──────────────────┐    ┌──────────────────┐
│  Laptop Scanner  │    │    VM Scanner    │          │   K8s Scanner    │    │  GitHub Scanner  │
│  (Host Audits)   │    │ (SSH to debianvm)│          │ (kubectl/API)    │    │  (GitHub REST)   │
└────────┬─────────┘    └────────┬─────────┘          └────────┬─────────┘    └────────┬─────────┘
         │                       │                             │                       │
         └───────────────────────┴──────────────┬──────────────┴───────────────────────┘
                                                │ POST /api/v1/posture
                                                ▼
                                    FastAPI Ingestion Gateway
                                                │
                                                ▼ INSERT
                                  ClickHouse: posture_findings
```

---

### Scanner 1: Laptop Workstation (`posture/scanners/laptop_scanner.py`)
- **Focus**: Workstation hardening and developer workstation hygiene.
- **Key Checks Executed**:
  1. `CIS-HOST-2.1` (**Kernel Core Dumps**): Audits `sysctl fs.suid_dumpable`. If set to `2` or `1`, SUID processes can dump core memory on crash, leaking passwords and tokens.
     - *Remediation*: `sysctl -w fs.suid_dumpable=0`.
  2. `CIS-HOST-1.1` (**Sensitive File Permissions**): Verifies `/etc/passwd` and `/etc/shadow` ownership and file permissions.
  3. `PKG-CVE-AUDIT` (**Installed Packages**): Queries local package manager for unpatched workstation libraries.

---

### Scanner 2: Real Linux VM (`posture/scanners/vm_scanner.py`)
- **Focus**: CIS Linux Server Benchmark & OS package vulnerabilities on Debian 12.
- **Mechanism**: Connects over SSH (`ssh debianvm`) and inspects system configuration files.
- **Key Checks Executed**:
  1. `CIS-VM-5.2.10` (**SSH Root Login**): Inspects `/etc/ssh/sshd_config` for `PermitRootLogin yes`.
     - *Remediation*: `sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd`.
  2. `CIS-VM-5.2.7` (**SSH MaxAuthTries**): Checks if brute-force thresholds are configured (`MaxAuthTries <= 4`).
  3. `CIS-VM-5.1.2` (**Cron Access Control**): Checks for the existence of `/etc/cron.allow` to restrict cron job creation.
  4. `CVE-2024-1086` (**Linux Kernel Netfilter UAF**): Checks kernel version against known privilege escalation flaws.
  5. `CVE-2023-4911` (**glibc "Looney Tunables"**): Checks `ld.so` glibc version for local root privilege escalation.

---

### Scanner 3: Kubernetes Infrastructure (`posture/scanners/k8s_scanner.py`)
- **Focus**: CIS Kubernetes Benchmark & Pod Security Standards (PSS).
- **Mechanism**: Connects via `kubectl` and queries the live Kubernetes API (`kubectl get pods -A -o json`).
- **Key Checks Executed**:
  1. `CIS-K8S-5.2.5` (**Privileged Containers**): Inspects running pods for `securityContext.privileged: true`.
     - *Remediation*: Remove `privileged: true` from container spec.
  2. `CIS-K8S-5.2.1` (**Host Filesystem Mounts**): Detects containers mounting the host root filesystem (`hostPath: /`).
  3. `CIS-K8S-5.1.5` (**ServiceAccount Token Automounting**): Checks whether workloads have `automountServiceAccountToken: true` on the default ServiceAccount.
     - *Remediation*: Set `automountServiceAccountToken: false` on pods that don't need to communicate with the Kubernetes API.
  4. `CIS-K8S-5.3.2` (**Missing Default Network Policies**): Verifies whether namespaces enforce default-deny NetworkPolicies.

---

### Scanner 4: GitHub Repository (`posture/scanners/github_scanner.py`)
- **Focus**: Source code governance, branch protection, and secrets exposure.
- **Mechanism**: Queries GitHub REST API (`gh api /repos/:owner/:repo`) and scans commit trees.
- **Key Checks Executed**:
  1. `CIS-GIT-1.0` (**Branch Protection Rules**): Checks if the `main` branch enforces pull request reviews, approvals, and status checks before merging.
     - *Remediation*: Enable branch protection rules on `main` via repository settings.
  2. `CIS-GIT-2.3` (**Public Wiki Attack Surface**): Detects if public wikis are enabled (a common vector for phishing or spam defacement).
  3. `GITHUB-SEC-001` (**Secret Scanning & Push Protection**): Verifies whether GitHub secret scanning and push protection are enabled.

---

## 4. What Dashboard Components Depend on `posture_findings`?

In the Grafana **Mini SIEM Overview Dashboard** (`/d/mini-siem-overview`), **Rows 1 and 2** are powered directly by this dataset:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ROW 1: Executive KPIs (Posture Driven)                                                 │
│ ┌─────────────────┬─────────────────┬─────────────────┐                                │
│ │ Panel 101       │ Panel 1         │ Panel 2         │                                │
│ │ Fleet Posture   │ Critical        │ High Severity   │                                │
│ │ Score (Gauge)   │ Posture Stat    │ Posture Stat    │                                │
│ │ 75% [WARNING]   │ 1               │ 2               │                                │
│ └─────────────────┴─────────────────┴─────────────────┘                                │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ROW 2: Security Posture Assessment (Vulnerabilities & Misconfigurations)               │
│ ┌──────────────────────────────┬──────────────────────────┬──────────────────────────┐ │
│ │ Panel 201                    │ Panel 202                │ Panel 203                │ │
│ │ Open Findings by Asset & Type│ Posture Severity Donut   │ Actionable Security      │ │
│ │ (Barchart: CVE vs Misconfig) │ (Distribution: Critical, │ Posture & Remediation    │ │
│ │ Laptop, VM, K8s, GitHub      │  High, Medium, Low)      │ Inventory Table          │ │
│ └──────────────────────────────┴──────────────────────────┴──────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Panel 101: Fleet Posture Health Score (0 - 100% Gauge)
- **What it shows**: The overall security health of your enterprise infrastructure as a single executive percentage.
- **The SQL Query**:
  ```sql
  SELECT 
      round(
          greatest(
              10, 
              100 - (
                  countIf(severity = 'CRITICAL' AND status = 'OPEN') * 5 + 
                  countIf(severity = 'HIGH' AND status = 'OPEN') * 3 + 
                  countIf(severity = 'MEDIUM' AND status = 'OPEN') * 1
              )
          ), 
          0
      ) AS posture_score
  FROM siem.v_latest_posture 
  WHERE asset_id IN ('SUSHANKYA', 'prod-linux-vm-01', 'kind-siem-k8s', 'ShudarsanRegmi/mini-siem-clickhouse');
  ```
- **How it works**: Starts at `100%`. Every open Critical finding subtracts `5%`, High subtracts `3%`, and Medium subtracts `1%`. Clamped to a minimum of `10%`.

### 2. Panel 1 & 2: Critical & High Posture Stat Counters
- Displays immediate counters of active vulnerabilities requiring urgent developer/sysadmin remediation:
  ```sql
  SELECT countIf(severity = 'CRITICAL' AND status = 'OPEN') AS count 
  FROM siem.v_latest_posture 
  WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type');
  ```

### 3. Panel 201: Open Findings by Asset & Type (Barchart)
- Breaks down whether your risk comes from **unpatched software (`vulnerability`)** or **poor system configuration (`misconfiguration`)** across each asset class:
  ```sql
  SELECT 
      asset_type, 
      countIf(finding_type = 'vulnerability' AND status = 'OPEN') AS vulnerabilities, 
      countIf(finding_type = 'misconfiguration' AND status = 'OPEN') AS misconfigurations 
  FROM siem.v_latest_posture 
  WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type') 
  GROUP BY asset_type 
  ORDER BY asset_type;
  ```

### 4. Panel 202: Posture Severity Distribution (Donut)
- Visual percentage split of open risk (Critical, High, Medium, Low).

### 5. Panel 203: Actionable Posture & Remediation Inventory (Table)
- The operational worklist for security teams. Displays every open issue, check ID, title, and the exact remediation command:
  ```sql
  SELECT 
      severity, asset_type, asset_id, finding_type, check_id, title, status, remediation 
  FROM siem.v_latest_posture 
  WHERE status = 'OPEN' AND ('$asset_type' = 'all' OR asset_type = '$asset_type') 
  ORDER BY severity, asset_type 
  LIMIT 50;
  ```

---

## 5. How to Run a Posture Scan & Verify Changes

To run an ad-hoc posture audit on all 4 assets:

```bash
cd mini-siem-clickhouse
.venv/bin/python posture/run_posture_scans.py --asset all
```

To scan an individual asset (e.g. only Kubernetes or only VM):
```bash
.venv/bin/python posture/run_posture_scans.py --asset k8s
.venv/bin/python posture/run_posture_scans.py --asset vm
```

To view the latest deduplicated findings in ClickHouse:
```bash
docker exec -i siem_clickhouse clickhouse-client \
  --user default \
  --password "$(grep CLICKHOUSE_ADMIN_PASSWORD .env | cut -d= -f2)" \
  --query "
SELECT asset_type, check_id, severity, status, title, remediation
FROM siem.v_latest_posture
WHERE status = 'OPEN'
ORDER BY severity, asset_type
FORMAT PrettyCompact;
"
```
