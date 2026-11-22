# ClickHouse SQL Survival Playbook: Database Exploration & SOC Telemetry Analysis

This survival playbook provides everything a Security Engineer or SOC Analyst needs to browse, explore, and run forensic threat hunting queries on the Mini SIEM ClickHouse database.

---

## 1. Quick Access: How to Run Queries

Because ClickHouse runs containerized inside `siem_clickhouse`, you do not need the native client installed on your host machine.

### Method A: One-Liner from Host Terminal (Recommended)
Run single queries directly from the `mini-siem-clickhouse` directory:

```bash
docker exec -i siem_clickhouse clickhouse-client \
  --user default \
  --password "$(grep CLICKHOUSE_ADMIN_PASSWORD mini-siem-clickhouse/.env | cut -d= -f2)" \
  --query "SELECT count() FROM siem.raw_telemetry FORMAT PrettyCompact;"
```

### Method B: Interactive ClickHouse CLI Prompt
Drop into an interactive shell (with tab-completion and query history):

```bash
cd mini-siem-clickhouse
docker exec -it siem_clickhouse clickhouse-client \
  --user default \
  --password "$(grep CLICKHOUSE_ADMIN_PASSWORD .env | cut -d= -f2)" \
  --database siem
```
*(Type `exit` or press `Ctrl+D` to disconnect).*

### Method C: Web Browser (Grafana Explore)
1. Open **[http://localhost:3000/explore](http://localhost:3000/explore)**.
2. Select the **ClickHouse** datasource (`P8301CFBB4E66FEF2`).
3. Toggle mode to **Code / SQL** and paste any query from this guide.

### Method D: HTTP REST API via curl
```bash
curl -s -u "default:$(grep CLICKHOUSE_ADMIN_PASSWORD mini-siem-clickhouse/.env | cut -d= -f2)" \
  "http://127.0.0.1:8123/?query=SELECT+count()+FROM+siem.raw_telemetry"
```

---

## 2. Database & Schema Discovery Playbook

Use these commands when you first enter ClickHouse to explore databases, tables, columns, and system resources.

### Explore Databases & Tables
```sql
-- List all databases
SHOW DATABASES;

-- List all tables and views in the siem database
SHOW TABLES FROM siem;

-- Show current active database
SELECT currentDatabase();
```

### Inspect Table Schemas & Column Data Types
```sql
-- Detailed schema of the raw telemetry table
DESCRIBE TABLE siem.raw_telemetry FORMAT PrettyCompact;

-- Detailed schema of posture findings (vulnerabilities & CIS checks)
DESCRIBE TABLE siem.posture_findings FORMAT PrettyCompact;

-- Detailed schema of detection alerts
DESCRIBE TABLE siem.security_alerts FORMAT PrettyCompact;

-- View the exact DDL statement used to create a table or view
SHOW CREATE TABLE siem.raw_telemetry;
SHOW CREATE TABLE siem.v_latest_posture;
```

### Inspect Storage, Partitions & Compression Ratios
ClickHouse uses columnar storage and LZ4/ZSTD compression. Run this query against `system.parts` to see the live footprint:

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
ORDER BY total_rows DESC
FORMAT PrettyCompact;
```
> [!NOTE]
> In our live SIEM, 400,000+ raw telemetry events (~440 MB uncompressed) take only **~19 MB** on disk — achieving an incredible **23x compression ratio**!

### Check Running Queries & Kill Long-Running Tasks
```sql
-- View currently executing queries
SHOW PROCESSLIST;

-- Check execution duration and memory of recent queries
SELECT query_id, user, elapsed, read_rows, formatReadableSize(memory_usage), query
FROM system.query_log
WHERE type = 'QueryFinish'
ORDER BY event_time DESC
LIMIT 5
FORMAT PrettyCompact;

-- Kill a hung or runaway query by query_id
-- KILL QUERY WHERE query_id = 'xxxx-xxxx-xxxx';
```

---

## 3. ClickHouse Superpowers & Output Formatting

ClickHouse supports unique formatting and functions that make SOC analysis much faster than standard PostgreSQL/MySQL.

### The Secret Weapon: Output Formats
Append `FORMAT <type>` to the end of any query:

| Format | When to Use |
|---|---|
| `FORMAT PrettyCompact` | Default readable ASCII table with clean borders. |
| `FORMAT Vertical` | **Must-know for SOC analysis**: Displays each column on its own line (`Row 1: timestamp: ... actor: ...`). Perfect for wide JSON logs or long command lines! |
| `FORMAT JSONEachRow` | Returns newline-delimited JSON for scripting or piping to `jq`. |
| `FORMAT CSVWithNames` | Exports query results with headers to CSV. |
| `FORMAT Null` | Executes query and discards output (ideal for benchmarking latency). |

#### Example of `FORMAT Vertical`:
```sql
SELECT timestamp, asset_id, actor, command_line, raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'vm' AND process_name = 'cat'
LIMIT 1
FORMAT Vertical;
```

### Crucial Concept: The `FINAL` Keyword
Our `siem.posture_findings` table uses the `ReplacingMergeTree` engine to deduplicate repeated vulnerability scans.
- In background operations, ClickHouse periodically collapses duplicate findings having the same primary key `(asset_type, asset_id, finding_type, check_id)`.
- When querying manually, append `FINAL` to force ClickHouse to resolve latest deduplicated rows on the fly:
  ```sql
  SELECT count() FROM siem.posture_findings;        -- May include historical versions
  SELECT count() FROM siem.posture_findings FINAL;  -- Guaranteed latest deduplicated state
  ```
- Alternatively, simply query the pre-built view `siem.v_latest_posture` which embeds `FINAL` automatically!

---

## 4. Specialized Analytical Functions for SOC Analysts

### 1. Conditional Counting (`countIf`, `sumIf`)
Avoid messy `CASE WHEN` statements. ClickHouse natively aggregates with conditions:
```sql
SELECT 
    asset_type,
    count() AS total_events,
    countIf(severity = 'CRITICAL') AS critical_events,
    countIf(severity = 'HIGH') AS high_events,
    countIf(actor = 'root' OR actor = 'system:anonymous') AS privileged_actors
FROM siem.raw_telemetry
GROUP BY asset_type
ORDER BY total_events DESC
FORMAT PrettyCompact;
```

### 2. Array Aggregations (`groupUniqArray`)
Collect a distinct list of processes, IPs, or users per asset into a clean array:
```sql
SELECT 
    asset_type,
    groupUniqArray(actor) AS distinct_actors,
    groupUniqArray(process_name) AS distinct_processes
FROM siem.raw_telemetry
WHERE process_name IS NOT NULL
GROUP BY asset_type
FORMAT PrettyCompact;
```

### 3. Native JSON Parsing (`JSONExtractString`, `JSONExtractInt`, `JSONHas`)
ClickHouse can parse JSON payloads inside text fields at gigabytes-per-second:
```sql
SELECT 
    timestamp,
    actor,
    JSONExtractString(raw_json, 'verb') AS k8s_verb,
    JSONExtractString(raw_json, 'requestURI') AS k8s_uri,
    JSONExtractString(raw_json, 'objectRef.resource') AS target_resource
FROM siem.raw_telemetry
WHERE asset_type = 'k8s' AND JSONExtractString(raw_json, 'verb') != ''
ORDER BY timestamp DESC
LIMIT 5
FORMAT PrettyCompact;
```

### 4. Time Bucketing (`toStartOfInterval`)
Group telemetry events into 5-minute or 1-hour histogram buckets:
```sql
SELECT 
    toStartOfInterval(timestamp, INTERVAL 1 HOUR) AS hour_window,
    asset_type,
    count() AS events_in_window
FROM siem.raw_telemetry
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY hour_window, asset_type
ORDER BY hour_window DESC, events_in_window DESC
LIMIT 10
FORMAT PrettyCompact;
```

---

## 5. Ready-to-Use Threat Hunting & SOC Analytical Queries

Here is a curated suite of forensic queries mapped directly to our Mini SIEM data.

---

### Investigation 1: Fleet Ingestion Velocity & Telemetry Share
**Goal**: Check data health, volume distribution, and event timestamps across all four asset classes.

```sql
SELECT 
    asset_type,
    asset_id,
    count() AS total_events,
    min(timestamp) AS earliest_seen,
    max(timestamp) AS latest_seen,
    round(count() * 100.0 / (SELECT count() FROM siem.raw_telemetry), 2) AS percentage_of_total
FROM siem.raw_telemetry
GROUP BY asset_type, asset_id
ORDER BY total_events DESC
FORMAT PrettyCompact;
```

---

### Investigation 2: Hunting Container Escapes & Privileged Pods (Kubernetes)
**Goal**: Identify pods launched with host root mounts (`/`) or `privileged: true` (MITRE T1610, T1611).

```sql
SELECT 
    timestamp,
    asset_id,
    actor,
    source_ip,
    target_resource,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'k8s'
  AND (
      position(raw_json, 'privileged') > 0 
      OR position(raw_json, 'hostPath') > 0
      OR position(raw_json, 'privileged-escape-pod') > 0
  )
ORDER BY timestamp DESC
LIMIT 3
FORMAT Vertical;
```

---

### Investigation 3: Hunting Unauthorized Pod Exec & Token Snooping (Kubernetes)
**Goal**: Detect interactive terminal sessions (`pods/exec`) inside non-system pods where attackers steal ServiceAccount JWT tokens (MITRE T1059, T1552.007).

```sql
SELECT 
    timestamp,
    actor,
    source_ip,
    target_resource,
    JSONExtractString(raw_json, 'verb') AS verb,
    JSONExtractString(raw_json, 'objectRef.namespace') AS namespace,
    JSONExtractString(raw_json, 'objectRef.name') AS pod_name,
    JSONExtractString(raw_json, 'requestURI') AS exec_uri
FROM siem.raw_telemetry
WHERE asset_type = 'k8s'
  AND (
      position(target_resource, 'exec') > 0 
      OR JSONExtractString(raw_json, 'objectRef.subresource') = 'exec'
  )
  AND JSONExtractString(raw_json, 'objectRef.namespace') != 'kube-system'
ORDER BY timestamp DESC
LIMIT 5
FORMAT PrettyCompact;
```

---

### Investigation 4: Hunting Credential Access & Shadow File Reads (Linux VM)
**Goal**: Trace unauthorized reads of `/etc/shadow` on the Debian VM (MITRE T1003).

```sql
SELECT 
    timestamp,
    asset_id,
    actor,
    source_ip,
    process_name,
    command_line,
    target_resource
FROM siem.raw_telemetry
WHERE asset_type = 'vm'
  AND (
      position(target_resource, 'shadow') > 0 
      OR position(command_line, 'shadow') > 0
  )
ORDER BY timestamp DESC
LIMIT 5
FORMAT PrettyCompact;
```

---

### Investigation 5: Hunting Linux Persistence & Reverse Shell Sockets (VM)
**Goal**: Uncover cron job tampering (`/etc/cron.d/sync_backdoor`) and socket redirections (`/dev/tcp/`) (MITRE T1053.003, T1059.004).

```sql
SELECT 
    timestamp,
    asset_id,
    actor,
    process_name,
    command_line,
    target_resource
FROM siem.raw_telemetry
WHERE asset_type = 'vm'
  AND (
      position(target_resource, 'cron') > 0 
      OR position(command_line, 'cron') > 0
      OR position(command_line, '/dev/tcp') > 0
      OR position(command_line, 'nc -e') > 0
  )
ORDER BY timestamp DESC
LIMIT 5
FORMAT PrettyCompact;
```

---

### Investigation 6: Hunting Leaked API Secrets & AWS Canaries (GitHub)
**Goal**: Scan GitHub commit audit webhooks for high-entropy secrets and AWS access keys (MITRE T1552.001).

```sql
SELECT 
    timestamp,
    asset_id AS repository,
    actor AS git_committer,
    event_type,
    JSONExtractString(raw_json, 'head_commit.message') AS commit_message,
    JSONExtractString(raw_json, 'head_commit.author.email') AS committer_email,
    raw_json
FROM siem.raw_telemetry
WHERE asset_type = 'github'
  AND (
      position(raw_json, 'AKIA') > 0 
      OR position(raw_json, 'secret_leak') > 0
      OR position(raw_json, 'ghp_') > 0
  )
ORDER BY timestamp DESC
LIMIT 2
FORMAT Vertical;
```

---

### Investigation 7: Vulnerability & CIS Benchmark Posture Triage
**Goal**: Check open security debt, unpatched CVEs, and insecure configurations across the entire enterprise.

```sql
SELECT 
    asset_type,
    asset_id,
    severity,
    finding_type,
    check_id,
    title,
    remediation
FROM siem.v_latest_posture
WHERE status = 'OPEN'
ORDER BY 
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END ASC
FORMAT PrettyCompact;
```

#### Executive Posture Rollup per Asset:
```sql
SELECT 
    asset_type,
    asset_id,
    critical_count,
    high_count,
    medium_count,
    low_count,
    total_open_findings,
    last_scanned_at
FROM siem.v_posture_summary
ORDER BY critical_count DESC, high_count DESC
FORMAT PrettyCompact;
```

---

### Investigation 8: Security Alerts Breakdown by MITRE ATT&CK Tactic
**Goal**: Identify which attack vectors are actively firing against your infrastructure.

```sql
SELECT 
    mitre_tactic,
    severity,
    count() AS total_alerts,
    groupUniqArray(rule_name) AS triggered_rules,
    groupUniqArray(asset_type) AS impacted_assets
FROM siem.security_alerts
GROUP BY mitre_tactic, severity
ORDER BY total_alerts DESC
FORMAT PrettyCompact;
```

---

### Investigation 9: Alert-to-Telemetry Correlation (End-to-End Investigation)
**Goal**: Pivot from a fired alert back to the exact raw evidence logs that triggered it.

```sql
SELECT 
    a.alert_id,
    a.triggered_at,
    a.rule_name,
    a.mitre_tactic,
    a.asset_type,
    a.asset_id,
    a.severity,
    a.evidence_context
FROM siem.security_alerts AS a
ORDER BY a.triggered_at DESC
LIMIT 3
FORMAT Vertical;
```

---

## 6. Performance Rules of Thumb for ClickHouse SIEM Queries

1. **Always Filter on `asset_type` and `timestamp` First**:
   - `siem.raw_telemetry` is sorted by `ORDER BY (asset_type, timestamp)`. Filtering on these two fields uses primary key index pruning and skips billions of unneeded bytes.
2. **Use String Search Functions Efficiently**:
   - Prefer `position(str, 'needle') > 0` or `ilike '%needle%'` over heavy regular expressions (`match()`) when searching for fixed keywords like `/etc/shadow` or `AKIA`.
3. **Always Add a `LIMIT` Clause**:
   - In terminal sessions, unbounded `SELECT *` can flood your terminal with thousands of lines. Cap explorations with `LIMIT 10 FORMAT PrettyCompact`.
4. **Use Views for Clean Dashboards**:
   - Use `siem.v_latest_posture` and `siem.v_posture_summary` rather than querying `posture_findings` directly, ensuring deduplication is handled automatically.
