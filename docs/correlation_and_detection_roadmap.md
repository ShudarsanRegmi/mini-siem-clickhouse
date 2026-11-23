# Log Correlation & Detection Engineering Analysis: Current State & Future Architecture

This analysis evaluates our current use of log correlation in the **ClickHouse Mini SIEM**, identifies architectural gaps, and provides concrete, battle-tested ClickHouse SQL implementations to level up our detection engine from atomic pattern matching to multi-stage kill-chain inference.

---

## 1. Honest Assessment: Current Correlation Maturity

In SOC and Detection Engineering, detection capability matures across four distinct stages:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              DETECTION MATURITY LEVELS                                 │
├────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
│ Level 1: Atomic Matching   │ Level 2: Entity Aggregation │ Level 3: Temporal Sequences │
│ (Single-log regex/keyword) │ (Group events by user/host) │ (Multi-stage kill chains)   │
├────────────────────────────┼─────────────────────────────┼─────────────────────────────┤
│ Level 4: Contextual Posture│ Level 5: Cross-Asset Blast  │ Level 6: Behavioral Baselines│
│ (Enrich logs with CVE debt)│ (Correlate Git ➔ VM ➔ K8s)  │ (Statistical rarity/spikes) │
└────────────────────────────┴─────────────────────────────┴─────────────────────────────┘
```

### Where We Are Today: Level 1 & Level 2
Currently, our detection rules operate at **Level 1 (Atomic Pattern Matching)** with **Level 2 (Entity Deduplication)**:

1. **Atomic Matching**: Each rule queries a single log stream in isolation:
   - Rule `SEC-VM-001`: Did any single auditd record touch `/etc/shadow`?
   - Rule `SEC-K8S-001`: Did any single Kubernetes audit record request `privileged: true`?
   - Rule `SEC-GIT-001`: Did any single commit diff contain `AKIA` or a `PRIVATE KEY`?
2. **Entity Deduplication**: In `detections/engine.py`, we group multiple matches by `(asset_id, actor)` within a 60-minute window into one consolidated incident alert (`matched_events_count = 29`), preventing alert flooding.

### What is Missing Today:
- **No Temporal Chaining**: We do not detect multi-step attack sequences (e.g. Inbound SSH ➔ Sudo ➔ File Read).
- **No Posture-to-Telemetry Correlation**: Our static vulnerability findings (`v_latest_posture`) and runtime telemetry (`raw_telemetry`) live in the same database but operate in silos.
- **No Cross-Asset Correlation**: Events on GitHub, Kubernetes, and Linux VMs are treated as independent worlds without shared identity or IP stitching.

---

## 2. Four Concrete Improvements to Level Up Detection

ClickHouse has specialized built-in analytical vector functions (`windowFunnel`, `sequenceMatch`, `ASOF JOIN`) that enable real-time multi-event correlation without needing heavy stream-processing clusters like Apache Flink or Spark.

---

### Improvement 1: Temporal Sequence Correlation (Chained Attack Paths)

#### The Problem:
An attacker rarely runs `cat /etc/shadow` out of thin air. Real intrusions follow a multi-stage sequence:
1. **Initial Access**: Inbound SSH login (`ssh_login_success` / `sshd-session`).
2. **Privilege Escalation**: Invoking elevated utilities (`sudo` / `su`).
3. **Action on Objectives**: Reading `/etc/shadow` or spawning a `/dev/tcp/` reverse shell.

#### The ClickHouse Solution: `sequenceMatch()`
ClickHouse's native **`sequenceMatch()`** function uses regular-expression syntax across chronological event conditions:

```sql
SELECT 
    asset_id,
    actor,
    sequenceMatch('(?1).*(?2).*(?3)')(
        toDateTime(timestamp),
        event_type = 'ssh_login_success' OR process_name = 'sshd-session', -- Stage 1: Inbound SSH
        process_name = 'sudo' OR event_type = 'sudo_command',             -- Stage 2: Privilege Escalation
        target_resource = '/etc/shadow' OR position(command_line, 'shadow') > 0 -- Stage 3: Credential Dump
    ) AS full_killchain_detected,
    min(timestamp) AS attack_started,
    max(timestamp) AS attack_completed
FROM siem.raw_telemetry
WHERE asset_type = 'vm' AND timestamp >= now() - INTERVAL 1 HOUR
GROUP BY asset_id, actor
HAVING full_killchain_detected = 1
FORMAT PrettyCompact;
```

#### Why This Is Superior:
- Eliminates false positives from benign administrative scans.
- Proves attacker progression: alerts only fire when the complete 3-stage chain succeeds within the time window.

---

### Improvement 2: Posture-Enriched Telemetry (Vulnerability-Aware Detections)

#### The Problem:
If an unknown binary executes on a fully patched, hardened system, it may be low risk. But if that same binary executes on a server that has an open **CRITICAL CVE** (such as `CVE-2024-1086` Netfilter privilege escalation), the risk is extreme.

#### The ClickHouse Solution: Real-Time Posture JOIN
Because `siem.v_latest_posture` and `siem.raw_telemetry` are co-located in ClickHouse, we can perform sub-millisecond contextual joins:

```sql
SELECT 
    t.timestamp,
    t.asset_id,
    t.actor,
    t.process_name,
    t.command_line,
    p.check_id AS active_vulnerability,
    p.title AS vulnerability_description,
    p.severity AS static_risk_level,
    -- Dynamic Risk Elevation: If the machine has unpatched critical CVEs, escalate to CRITICAL
    CASE 
        WHEN p.severity = 'CRITICAL' THEN 'CRITICAL'
        WHEN p.severity = 'HIGH' THEN 'HIGH'
        ELSE t.severity
    END AS contextual_alert_severity
FROM siem.raw_telemetry AS t
INNER JOIN siem.v_latest_posture AS p 
  ON t.asset_type = p.asset_type AND t.asset_id = p.asset_id
WHERE t.asset_type = 'vm'
  AND t.timestamp >= now() - INTERVAL 1 HOUR
  AND p.status = 'OPEN'
  AND (t.process_name = 'sudo' OR t.target_resource LIKE '%shadow%')
ORDER BY t.timestamp DESC
LIMIT 10
FORMAT PrettyCompact;
```

#### Why This Is Superior:
- Bridges static posture with dynamic detection.
- Alerts automatically carry vulnerability context, so the SOC analyst immediately knows: *"This command ran on an unpatched server vulnerable to CVE-2024-1086."*

---

### Improvement 3: Cross-Asset Blast Radius Correlation (Identity & Token Stitching)

#### The Problem:
Adversaries pivot between environments:
1. Steal or leak a cloud token on **GitHub**.
2. Use that token to authenticate against the **Kubernetes API** or access an **AWS / S3 bucket**.
3. Move laterally into the **Linux VM**.

#### The ClickHouse Solution: Entity Stitching via Actor or Token
We can query across distinct `asset_type` values to correlate activities sharing an identity or token fingerprint within a sliding 2-hour window:

```sql
SELECT 
    git.actor AS committer,
    git.timestamp AS git_leak_time,
    k8s.timestamp AS k8s_access_time,
    dateDiff('minute', git.timestamp, k8s.timestamp) AS minutes_between_events,
    git.target_resource AS git_repo,
    k8s.target_resource AS k8s_resource
FROM siem.raw_telemetry AS git
INNER JOIN siem.raw_telemetry AS k8s
  ON (
      -- Match on committer login matching Kubernetes user/actor
      git.actor = k8s.actor
      OR position(k8s.raw_json, JSONExtractString(git.raw_json, 'head_commit.id')) > 0
  )
WHERE git.asset_type = 'github' 
  AND k8s.asset_type = 'k8s'
  AND git.event_type LIKE '%secret_leak%'
  AND k8s.timestamp >= git.timestamp
  AND k8s.timestamp <= git.timestamp + INTERVAL 2 HOUR
FORMAT PrettyCompact;
```

#### Why This Is Superior:
- Detects the entire **attack blast radius** across cloud, code, and infrastructure.

---

### Improvement 4: Statistical Anomaly Profiling (Rare Process Execution)

#### The Problem:
Attackers often rename binaries or use unusual tools (`socat`, `ncat`, `chattr`, `whoami`) that legitimate users rarely touch. Signature rules looking for specific keywords miss zero-day or custom tooling.

#### The ClickHouse Solution: Baseline Rarity Scoring (`count() OVER (...)`)
ClickHouse can calculate baseline frequency of binaries across the fleet on the fly:

```sql
SELECT 
    timestamp,
    asset_id,
    actor,
    process_name,
    command_line,
    historical_executions
FROM (
    SELECT 
        timestamp,
        asset_id,
        actor,
        process_name,
        command_line,
        count() OVER (PARTITION BY process_name) AS historical_executions
    FROM siem.raw_telemetry
    WHERE asset_type = 'vm' AND process_name IS NOT NULL
)
-- Flag processes that have executed fewer than 3 times in the entire telemetry history
WHERE historical_executions <= 2
ORDER BY timestamp DESC
LIMIT 10
FORMAT PrettyCompact;
```

#### Why This Is Superior:
- Discovers "living-off-the-land" binaries and zero-day execution without needing predefined static signatures.

---

## 3. Summary: Detection Engineering Roadmap

| Correlation Type | Current Implementation | Proposed Improvement | ClickHouse Function / Operator |
|---|---|---|---|
| **Temporal Chaining** | None (Single event matches) | Multi-stage kill-chain detection (Login ➔ Sudo ➔ Dump) | `sequenceMatch('(?1).*(?2).*(?3)')`, `windowFunnel()` |
| **Vulnerability Context** | Siloed in `v_latest_posture` | Contextual severity elevation based on unpatched CVEs | `INNER JOIN siem.v_latest_posture` |
| **Cross-Asset Pivoting** | Siloed per `asset_type` | Identity & token tracking (GitHub leak ➔ K8s exec) | Cross-asset `INNER JOIN` on actor/IP |
| **Anomaly Profiling** | Static rule thresholds | Baseline rarity scoring for unusual processes | `count() OVER (PARTITION BY process_name)` |
