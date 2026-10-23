# Architecture

**English | [中文](architecture.md)**

> Last updated: 2026-09-03 | Applies to: v2.x (seven-service backend)

## Overview

MxCwpp Platform uses a layered **Agent + Plugin + seven-service backend** architecture. The backend is split into seven independent services, **Manager / AgentCenter / Consumer / Engine / LLMProxy / VulnSync / Scanner**, each deployed and scaled independently. The control plane is stateless and supports horizontal scaling with multiple instances; the data plane is decoupled asynchronously through Kafka and writes in tiers according to storage characteristics: MySQL (business master data) and ClickHouse (time series and event archive).

### The seven services at a glance

| Service | Entry point | Responsibilities |
|------|------|------|
| Manager | `cmd/server/manager/main.go` | HTTP API, console backend, task dispatch, service discovery registry |
| AgentCenter | `cmd/server/agentcenter/main.go` | Agent gRPC ingestion and data forwarding, Kafka producer |
| Consumer | `cmd/server/consumer/main.go` | Kafka persistence (MySQL/ClickHouse), DLQ handling |
| Engine | `cmd/server/engine/main.go` | Detection and analysis engine: CEL/sequence/ML/Storyline/K8s Audit/RASP/Microseg |
| LLMProxy | `cmd/server/llmproxy/main.go` | Multi-vendor LLM adapter gateway: alert analysis / Storyline summaries / NL2Query |
| VulnSync | `cmd/server/vulnsync/main.go` | Fusion of 11+ vulnerability intelligence sources (NVD/OSV/RHSA/CNNVD/EPSS, etc.) |
| Scanner | `cmd/server/scanner/main.go` | Image scanning: claims jobs from scan_jobs, invokes trivy, writes results back to image_scans |

## System topology

```
                         +--------------------------+
                         |      User / Browser      |
                         +------------+-------------+
                                      | HTTPS
                                      v
                         +--------------------------+
                         |         Nginx            |
                         +------------+-------------+
                       /api/*         |         static assets
                +---------------------+--------------------+
                v                                          v
      +--------------------+                    +--------------------+
      |     Manager x N    |                    |    Next.js SPA     |
      | REST API / SD reg. |                    +--------------------+
      +-------+------------+
              |
              |  internal HTTP calls
              v
      +-------+------------+   +--------------------+   +--------------------+
      |   LLMProxy x N     |   |    Engine x N      |   |   VulnSync x N     |
      | LLM Gateway        |   | Detect (16 stages) |   | Vuln intel fusion  |
      +--------------------+   +-------+------------+   +-------+------------+
                                       ^                        |
                                       | Kafka mxcwpp.agent.*    | Kafka mxcwpp.vuln.advisory
                                       |                        v
      +--------------------+   +-------+------------+   +--------------------+
      |   AgentCenter x N  |--→| Kafka (KRaft x 3)  |←--|   Consumer x N     |
      | gRPC ingest/relay  |   | 8 biz Topics + DLQ |   | MySQL/ClickHouse   |
      +---------+----------+   +--------------------+   +--------------------+
                | gRPC BiDi Stream / mTLS
                v
      +------------------------------------------------------+
      |          mxcwpp-agent (on every target host)         |
      |  plugin host + lifecycle management + service disc.  |
      |  baseline / collector / fim / scanner / remediation  |
      |  avscanner / rasp-go / rasp-java/python/php/node     |
      |  EDR/eBPF runtime detection built into the agent     |
      |  (13 submodules)                                     |
      +------------------------------------------------------+

Storage layer (shared): MySQL 8 / Redis 7 / ClickHouse 24 / Prometheus
```

## Component responsibilities

### Manager

Management-plane HTTP API service, stateless, load-balanced behind Nginx.

- Provides 100+ REST API endpoints with JWT authentication
- Business CRUD for policies, rules, tasks, alerts, reports, users, etc.
- Vulnerability management: multi-source vulnerability database sync (OSV.dev / NVD / Red Hat) + host vulnerability scanning
- LLM-assisted alert analysis (`internal/server/llmproxy/llm_assist.go`)
- SBOM export (CycloneDX format, `internal/server/manager/api/sbom.go`)
- Notification service: alert notification delivery and management. Alert events published by the services are written to `alert_notify_events`; the single dispatcher inside manager
  (`alertbus.Dispatcher`) matches channels (host scope by category, severity, business line, etc.), deduplicates, sends, retries and records delivery
- Embedded AC Registry / SD module, responsible for AgentCenter registration, active health probing and service discovery
- Task scheduling: Redis distributed lock, 5s scheduling interval
- Queries MySQL / ClickHouse / Redis / Prometheus to aggregate frontend data
- Task dispatch: looks up the Redis `agent:ac` mapping to route precisely to the target AC
- Dashboard statistics and monitoring metrics use singleflight against thundering herds; when the cache expires only one goroutine starts the computation

Entry point: `cmd/server/manager/main.go`

### AgentCenter

Agent access layer. Its core responsibilities are connection management and data forwarding; it also depends on MySQL for business operations such as task distribution, policy lookups and asset writes.

- Maintains the pool of Agent gRPC bidirectional stream connections
- gRPC Keepalive parameters: Time=60s, Timeout=10s, MinTime=10s
- mTLS supports VerifyClientCertIfGiven (allows a first connection without a certificate so the certificate can be issued)
- Routes data reported by Agents to Kafka Topics by DataType
- When Kafka is unavailable, buffers in an in-memory fallback queue and replays automatically after recovery
- HTTP management interface: `/health` (anonymous liveness) + `/conn/stat` `/conn/list` `/command` `/command/batch` `/dependency/install` (mandatory `X-Internal-Secret` internal authentication; see "Security and communication")
- Registers with Manager SD on startup (3 retries), 15s heartbeat (including ConnCount), graceful deregistration
- Host performance metrics are exposed via `/metrics` for Prometheus scraping
- 8 built-in schedulers (`internal/server/agentcenter/scheduler/`): plugin update, Agent update, Agent restart,
  task timeout, heartbeat timeout detection, plugin push timeout, **IOC sync**, **rule sync**
- Background scheduler startup self-check: each scheduler calls `MarkStarted` in `Start`; after startup the list is compared against
  `ExpectedSchedulers`, and anything missing produces an ERROR log and sets the `mxcwpp_ac_scheduler_missing` metric to 1.
  This is not redundant: AC once had two initialization files side by side, and the wiring for IOC sync and rule sync was written only in
  the one with no callers. Wiring omissions like this go unnoticed for a long time: it compiles, starts normally, the logs are clean,
  yet the agent-side IOC set is empty and rules cannot be hot-updated.
  A static checklist cannot catch this kind of problem (the line really "exists" in the code, just in a dead file);
  only runtime facts can

Entry point: `cmd/server/agentcenter/main.go`

### Consumer

Asynchronous Kafka consumer service, **responsible only for data persistence** (detection lives in the Engine service).

- Subscribes to 8 business Topics (ConsumerGroup A "mxcwpp-consumer") and routes writes to MySQL / ClickHouse by DataType
- Idempotent writes: MySQL `ON DUPLICATE KEY UPDATE` (row-by-row upsert), ClickHouse `ReplacingMergeTree`
- Batching: ClickHouse 5000 rows / 10s
- Failed writes go to the Dead Letter Queue (`{sourceTopic}.dlq` Topic)
- DLQ messages keep the original message body, error message, retry count and failure time
- Consumption failures go to the DLQ instead of blocking on retries; however, **when a ClickHouse flush fails, the commit barrier does not advance the offset**,
  and the messages are redelivered (better to have extra duplicate rows in the archive than to commit "persisted" when nothing was actually persisted)
- Kafka ConsumerGroup configuration: RoundRobin rebalance strategy, OffsetNewest
- While consuming heartbeats, maintains the Redis `agent:ac:{agentID}` mapping and checks pending tasks to trigger re-dispatch
- GCP Pub/Sub consumption (`internal/server/consumer/gcppubsub/`): receives GKE audit logs from Cloud Logging

Entry point: `cmd/server/consumer/main.go`

### Engine

Detection and analysis engine, an independent service that consumes Kafka in parallel with Consumer.

- Subscribes to all `mxcwpp.agent.*` business Topics (ConsumerGroup B "mxcwpp-engine"); its offsets are independent of Consumer's
- **Detection Stages** (`internal/server/engine/stage_*.go`): `capability.go` is the authoritative list;
  of the 14 currently defined, **13 are wired into the pipeline**: CEL / Sequence / IOC / PortScan / Storyline /
  Privilege / RASP / Anti-Rootkit / Rootkit / ReverseShell / PrivEscalation /
  BruteForce / Webshell.
  Only `abnormal_login` is not wired (profile cold start would raise a false positive on every host's first login; see the roadmap)
- Multi-layer detection subpackages:
  - `celengine/` — CEL rule engine, real-time matching of eBPF events.
    Rules are graded `draft → shadow → context → alert`; the promotion threshold is determined by human triage verdicts
    (see [API · Rule lifecycle](../reference/api-reference.md#规则生命周期));
    ML anomaly scores take part in alert ranking via `host_anomaly_scores`, with the weight capped at 1.15, so they cannot cross a severity tier
  - `intrusion/` — intrusion detection collection (abnormal_login / reverse_shell / rootkit / webshell)
  - `adaudit/` — AD/LDAP domain controller audit, 7 rules (DCSync / Kerberoasting / brute force, etc.)
  - `microseg/` — microsegmentation traffic identification + policy generation + Kubernetes NetworkPolicy recommendations
  - `kube/` — K8s Audit Event detection (PSS, etc.)
  - `rasp/` — RASP event aggregation (Java / Python / PHP / Node / Go)
  - `honeypot/` — anti-ransomware / honeypot alert merging. **Under development and validation**: policy CRUD works,
    but `RecordDeployment` has zero callers (not wired on the agent side)
  - `ml/` — Go-native IForest + Registry. **Not wired** (capability list `ml_anomaly` = unwired),
    and **there is no ONNX**: go.mod has no onnxruntime dependency, and the ONNX adapter is still a TODO
  - `anomaly/` — behavioral baseline anomaly detection (IForest + multi-metric correlation). Four tiers `off/shadow/context/ranking`;
    **1.0 does not offer the alert tier**; includes a long-term reference baseline (resistant to training poisoning), model versioning and rollback, and per-host-quota training sampling.
    See [ML anomaly detection safety notes](../reference/ml-anomaly-safety.md)
  - `baseline/` — BDE per-host behavioral baseline (EWMA, graduates after a full 7 days of learning). Deviations are written as `behavior_alerts` detail records
    and are also merged into the main alert table (`source=behavior`, `rule_id=bde-<metric>`), where they can be triaged, allowlisted and notified;
    triage verdicts (false positive / benign counted as noise) feed back into per-metric threshold multipliers, adjusted only once there are 50 closed alerts within 14 days
  - `storyline/` — ATT&CK attack chain correlation and timeline
  - `ruleimport/` / `rulesync/` — Sigma/Falco/Tetragon rule import and sync
  - `scheduler/` — schedulers for IOC sync, rule sync, vulnerability intelligence sync, etc.
  - `rollout/` — staged (canary) rule rollout
- Output: `mxcwpp.engine.alert` / `mxcwpp.engine.storyline` / `mxcwpp.engine.feedback`

Entry point: `cmd/server/engine/main.go`

### LLMProxy

Multi-vendor LLM adapter gateway providing a unified Provider abstraction.

- **7 Providers**: OpenAI / Anthropic / Gemini / DashScope / DeepSeek / Ollama / vLLM
- **4 scenario routes**: alert_explain (alert interpretation) / storyline_summary (attack chain summary) / nl2query (natural language to query) / rule_draft (rule drafting)
- Redis 24h cache: input SHA256 → response mapping; a hit is returned directly
- Automatic fallback when the primary vendor fails: 3 consecutive failures blacklist it for 5min
- Per-tenant token limit + monthly cost (USD) alerting
- Audit: every call goes to Kafka `mxcwpp.llm.audit`

Entry point: `cmd/server/llmproxy/main.go`

### VulnSync

Vulnerability intelligence fusion service that periodically pulls authoritative advisories from OS vendors.

- **OS advisory sources**: RHSA / Rocky / USN / Debian / Alpine / CentOS + 4 Xinchuang (domestic IT) sources (producing matchable advisories with NEVRA + fixed_version + OS gate)
- Each advisory is pushed via `advisory.AdvisoryMessage` to Kafka `mxcwpp.vuln.advisory`
- **Manager consumer** (ConsumerGroup `mxcwpp-manager-vulnadvisory`) consumes → `advisory.Matcher` compares against host software inventories → writes `host_vulnerabilities` (the same `IngestAdvisories` write path as advisories)
- `POST /sync` triggers an immediate pull manually; Leader Election (redsync) prevents duplicate fetching by multiple replicas
- Still kept on the Manager side: OSV/language packages (PURL-driven `SyncByPURLs`) + NVD/MITRE/CNNVD/KEV/EPSS metadata enrichment (not time-incremental, so not part of VulnSync)

> Note: Engine's consumer for `mxcwpp.vuln.advisory` is currently a noop placeholder; correlation detection will be introduced in a later PR.
> Fusion of NVD/KEV/EPSS and other metadata (3-level confidence arbitration) is future work; VulnSync currently focuses on the OS advisory matching path.

Entry point: `cmd/server/vulnsync/main.go`

### Agent

A lightweight daemon deployed on target hosts. It provides no security capability by itself; all capabilities are implemented through plugins.

- Plugin lifecycle management (start, stop, upgrade, crash restart, watchdog health checks)
- gRPC bidirectional stream communication (mTLS), ring buffer of 2048 entries + 100ms batch sending + Snappy compression
- Service discovery: queries the Manager SD interface for the list of healthy ACs, power-of-two-choices load balancing
- The first connection may skip certificate verification to obtain a certificate; subsequent connections switch to full mTLS
- Data pass-through; plugin content is not parsed

Entry point: `cmd/agent/main.go`

### Plugins

Each plugin is an independent child process that communicates with the Agent via `os.Pipe` + Protobuf.

| Plugin | Function | Trigger |
|------|------|---------|
| baseline | Baseline checks + automatic remediation (9 checkers) | Task dispatch / scheduled |
| collector | Asset collection (11 collectors) | Scheduled (1-12h) |
| fim | File integrity monitoring (VM only) | Task dispatch |
| scanner | Malware scanning (ClamAV + YARA-X) + quarantine | Task dispatch / scheduled |
| avscanner | Standalone AV scanning engine (on-demand / real-time scanning) | Task dispatch / file events |
| remediation | Vulnerability remediation execution (supports dry-run) | Task dispatch |
| rasp-go | RASP probe for Go applications | Application injection |
| rasp-java | Java JVMTI Agent | -javaagent injection |
| rasp-python | Python sys.settrace hook | import hook |
| rasp-php | PHP Zend extension | Loaded via php.ini |
| rasp-node | Node.js inspector hook | --require injection |

EDR/eBPF runtime event collection (formerly the sensor/tetragon plugin) is now **built into the agent** and is no longer a separate plugin.

Agent built-in EDR submodules (`internal/agent/edr/`):

| Submodule | Capability |
|---|---|
| collector | eBPF + Tetragon process / file / network event collection |
| rootkit | Scans for DKOM-hidden PIDs / kernel modules / ports / LD_PRELOAD / /proc inconsistencies |
| honeypot | SSH / HTTP fake-response honeypot. **Not wired**: zero importers, the agent does not assemble it |
| canary | Anti-ransomware / anti-lateral-movement decoy files. **Not wired**: zero importers; the one actually running is the implementation inside `plugins/avscanner` |
| forensics | In-memory threat forensics (memfd_exec / process hollowing / shellcode / LSASS dump) |
| memfd | memfd_create fileless (in-memory) malware detection |
| bde | Boot Disk / filesystem encryption detection (anti-ransomware) |
| npatch | eBPF cgroup_skb (4.10+) + AF_PACKET v3 (CentOS 7 fallback) hot patching |
| lsm | LSM bpf hooks |
| fanotify | fanotify file event subscription |
| container | Container escape detection |
| elfparse | ELF binary parsing (malicious code identification) |
| weakpass | Weak password detection |
| ioc | IOC hit matching |
| storyline | Local attack chain aggregation |
| rule | Local rule engine (CEL subset) |
| event | Event bus |
| aggregator | Event aggregation |
| antidebug | Agent self anti-debugging |
| selfprotect | Agent self-protection |
| isolate | Isolation action execution |
| quarantine | File quarantine |
| av | ClamAV daemon integration |
| rasp | RASP event receiver (works with the rasp-* plugins) |
| yara | YARA-X precompiled rule matching (73 rules / 50 families) |

For the engine layer `internal/server/engine/`, see the [Engine](#engine) section above.

The plugin shared library `plugins/lib/go/` provides the standard interface for plugin–Agent communication.

## Data paths

### Reporting path (Agent -> storage + detection)

```
Plugin --> Agent Ring Buffer --> gRPC(mTLS) --> AgentCenter
    --> Kafka (routed to Topic by DataType)
    ├── ConsumerGroup A "mxcwpp-consumer" --> MySQL / ClickHouse / Redis (persistence)
    └── ConsumerGroup B "mxcwpp-engine"  --> 16-Stage pipeline (detection)
                                            --> mxcwpp.engine.alert/storyline/feedback
                                            --> Consumer persists alerts + attack chains
```

Engine and Consumer use different ConsumerGroups with **independent offsets**; a failure in either one does not affect the other.

### Dispatch path (user -> Agent)

```
User/API --> Manager --> look up SD + Redis(agent:ac) --> call target AC HTTP interface
    --> AC gRPC dispatch --> Agent --> routed to the corresponding plugin for execution
```

### Query path (frontend -> storage)

| Query scenario | Data source |
|---------|--------|
| Host/policy/task/alert status | MySQL |
| Monitoring metric curves/trend charts | Prometheus |
| FIM event lists/statistics | ClickHouse (preferred), MySQL (fallback) |
| Baseline scores | Redis cache |
| Dashboard trends | ClickHouse materialized views |

## Kafka design

Topics are grouped by data write characteristics, each with its own Retention and Partition strategy:

| Topic | DataType | Partitions | Retention | Description |
|-------|----------|-----------|-----------|------|
| `mxcwpp.agent.heartbeat` | 1000, 1001 | 6 | 24h | Heartbeat/plugin status -> MySQL |
| `mxcwpp.agent.events` | 6001, 6002 | 12 | 72h | FIM file integrity events -> ClickHouse |
| `mxcwpp.agent.baseline` | 8000-8004 | 6 | 7d | Baseline results/task completion -> MySQL |
| `mxcwpp.agent.asset` | 5050-5060 | 6 | 7d | Asset data -> MySQL |
| `mxcwpp.agent.scanner` | 7000-7004 | 6 | 7d | Malware scan results -> MySQL |
| `mxcwpp.agent.ebpf` | 3000-3002 | 12 | 3d | eBPF runtime events -> ClickHouse |
| `mxcwpp.agent.remediation` | 9100-9299 | 6 | 7d | Vulnerability remediation task results -> MySQL |
| `mxcwpp.agent.command-ack` | 9999 | 6 | 7d | Agent command execution results |

> **DataType allocation details**: for the complete DataType allocation table, routing map and checklist for adding new types, see [docs/development/datatype-allocation.md](datatype-allocation.md).
> **Note**: 6004 (FIM baseline snapshot) is handled directly on the AC side and does not go through Kafka; 9000/9001 are internal plugin SDK heartbeats and must not be used for business data.

The Partition Key is the AgentID, which keeps data from the same Agent ordered. Replication Factor = 2, `min.insync.replicas = 1`.

Each Topic has a matching DLQ: `mxcwpp.agent.{topic-name}.dlq`. The DLQ message structure contains the original message body, error description, number of retries so far and failure timestamp.

**Replay**: `cmd/tools/dlq-replay` sends DLQ messages back to the original Topic, returning them to the normal consumption path.

```bash
dlq-replay -config /etc/mxcwpp/server.yaml -topic mxcwpp.agent.events           # dry run
dlq-replay -config /etc/mxcwpp/server.yaml -topic mxcwpp.agent.events -apply    # execute
```

**ClickHouse write failures**: rows that Consumer cannot write to ClickHouse stay in memory and are retried in chunks; until they are persisted, the commit barrier does not advance the offset.
If the same table cannot be written for 2 consecutive minutes (or the backlog grows too large), its backlog is spilled to `mxcwpp.consumer.ch-spill` (sent synchronously,
waiting for acknowledgement from all replicas) and then cleared, and the offset resumes advancing, so a failure in one table cannot block the whole Consumer indefinitely. Rows rejected because their values do not match the table schema
are also spilled, not discarded. After a spill the `MxCwppConsumerCHSpilled` alert fires; once fixed, use `cmd/tools/ch-spill-replay`
to write them back (unlike the DLQ, what is spilled is parsed rows, not raw messages):

```bash
ch-spill-replay -config /etc/mxcwpp/server.yaml          # count pending replay
ch-spill-replay -config /etc/mxcwpp/server.yaml -apply   # write back to ClickHouse
```

By default, replay stops without committing when it hits rows that are still rejected (fix the table schema first); to confirm giving them up, add `-skip-rejected`. The number of records pending replay is in the metric
`mxcwpp_consumer_ch_spill_pending_records`, and the `MxCwppConsumerCHSpillPendingReplay` alert stays on until replay finishes.
Individual rows that cannot be serialized or exceed 1MB are not spilled; they are isolated and dropped, and the `MxCwppConsumerCHRowsDropped` alert fires (the log includes host_id).
Known limitation: spills are serialized as JSON, so non-UTF-8 bytes (such as non-UTF-8 file paths on Linux) are replaced with U+FFFD,
and the values written back by replay are not fully identical to the original reports; for forensics, the original Kafka messages are authoritative.

Replay is deliberately manual rather than automatic: the DLQ contains both messages caused by transient downstream failures, which recover on replay,
and poison messages such as those with invalid fields, which fail again no matter how many times they are replayed; automatic replay would make the latter loop between queues forever.
By default it is a dry run that neither delivers nor advances the position; messages above `-max-retry` (default 3) are treated as poison messages and skipped;
delivery uses a synchronous producer and advances the position only after success is confirmed, so if it fails midway it can simply be rerun.

## Storage tiers

| Store | Role | Writers |
|------|------|--------|
| MySQL 8.0+ | Business master data (hosts, policies, tasks, alert status, asset snapshots, users) | Consumer / Manager |
| ClickHouse | Time-series analysis and event archive (metric trends, FIM, alert timelines, audit logs) | Consumer |
| Redis | SD sync, `agent:ac` mapping, distributed locks, baseline score cache, thundering-herd protection | Manager / Consumer |
| Prometheus | Query source for host performance metrics (CPU / memory / disk / network) | AgentCenter Exporter |

### Data retention: two mechanisms, each covering one side

The `retention_policies` table defines the retention days for each kind of data, but it is **only ever applied as a ClickHouse
TABLE TTL** (when `admin_data_config` changes a retention period it runs `ALTER TABLE ... MODIFY TTL`).

Meanwhile `feature_flag.data_source.*` decides which side the same kind of data is actually written to, and all defaults are `mysql`.
Combined, the result is: data is written to MySQL, the retention period only takes effect on ClickHouse, and these tables on the MySQL side only grow,
eventually filling the disk.

The MySQL side is now cleaned independently by `manager/scheduler/mysql_retention.go`, one round every 6 hours,
deleting in batches to avoid long transactions locking tables. Two constraints:

- **An allowlist rather than iterating over all tables**. These tables do not share semantics: in `kernel_modules` almost every host
  has only a single `collected_at`; it is an overwritten current snapshot, not a historical log, and deleting by time would
  wipe out asset data. Snapshot tables need "keep the latest N copies per host", which is outside the scope of this mechanism.
- **Only clean hosts that are still reporting** (`ScopedToLiveHosts`). After a host stops reporting, all its historical rows will eventually
  pass the retention period and its last known state would simply vanish, yet these are exactly the hosts that most need
  data during an investigation. Data for hosts that stopped reporting is kept as-is until the host itself is decommissioned.
- **Tables with a lifecycle only delete finished items** (`OnlyStatuses`). `storylines` are set to `closed` by the storyline engine
  after 1 hour with no new events, and reopened when new events arrive for the same story_id; retention
  (policy key `storylines`, default 90 days, same as the details) only deletes `closed` / `resolved`;
  ones still in progress are kept no matter how old. Without the close step, `active` only grows, and counts and event correlation
  are both taken from `active`, so the bigger the table the slower they get.

Changing a data source (`data_source.*` from `mysql` to `ch`) requires restarting the corresponding process: the write target reads the flag once
at startup and does not change dynamically at runtime.

## Redis cache design

In this system Redis handles several responsibilities: service discovery sync, routing maps, distributed locks, business caches, and more. The full description of each key pattern follows:

| Key pattern | TTL | Purpose |
|---------|-----|------|
| `ac:instances` (Hash) | 120s | AC instance registry. The field is instanceID, the value is the JSON-serialized ACInstance struct |
| `ac:sd:changed` (Pub/Sub) | - | AC state change notification channel, syncs SD changes in real time across multiple Manager replicas |
| `agent:ac:{agentID}` | 180s | Mapping from Agent to AC instance, used for precise routing during task dispatch |
| `baseline:score:{hostID}` | Configurable | Baseline score cache, avoids recomputation |
| `mxcwpp:cache:dashboard:stats` | 30s | Dashboard statistics cache, used with singleflight against thundering herds |
| `mxcwpp:cache:monitor:host:{range}` | 60s-10m | Host monitoring metrics cache, with different TTLs for different time ranges |
| `mxcwpp:seq:{ruleID}:{hostID}` | rule.Window | Intermediate state for sequence detection; the TTL follows the rule's time window |
| `mxcwpp:task:dispatch:lock` | 8s | Distributed lock for task scheduling |
| `mxcwpp:virusdb:update:lock` | 10m | Distributed lock for virus database updates |
| `mxcwpp:ioc:{type}` (Set) | 24h | Threat intelligence IOC set |
| `scan:ports:{hostID}:{remoteAddr}` (SortedSet) | 60s | Sliding window for port scan detection |
| `scan:cd:{sourceAddr}` | 300s | Port scan alert cooldown |
| `scan:campaign:{sourceAddr}` (Set) | 24h | Set of hosts for which an external source has triggered port scan alerts, used for cross-asset escalation |
| `scan:days:{sourceAddr}` (Set) | 30d | Dates on which an external source triggered port scan alerts, used to identify return visits on later days |

## High availability design

### Service discovery (SD) implementation

Manager embeds a Registry struct that manages the lifecycle of all AgentCenter instances:

**Registration and heartbeat**

- On startup AC registers with the Manager SD module; registration failures are retried automatically 3 times
- AC sends a heartbeat every 15s, including its current ConnCount (number of connections)
- Heartbeat info is written to a Redis Hash: key `ac:instances`, field instanceID, value the JSON-serialized ACInstance struct, TTL 120s

**Multi-replica sync**

- Multiple Manager replicas sync SD changes in real time via Redis Pub/Sub (channel `ac:sd:changed`)
- A 30s full sync acts as a fallback, preventing state inconsistency caused by lost Pub/Sub messages

**Health probing**

- Key parameters: probeInterval=10s, probeTimeout=3s, unhealthyThreshold=3 times, heartbeatTTL=60s
- Active probing method: HTTP GET `/health`, 3s timeout
- After 3 consecutive failed probes the instance is marked unhealthy and removed from the available list

**Agent routing**

- During task dispatch, the Redis key `agent:ac:{agentID}` (TTL 180s) is looked up to route precisely to the AC instance the Agent is connected to
- If precise routing fails, it falls back to broadcast mode and sends the command to all healthy AC instances

### Existing HA capabilities

| Component | Method | Notes |
|------|------|------|
| Manager | xN replicas + Nginx least_conn | Stateless, JWT authentication, shared Redis cache |
| AgentCenter | xN replicas + L4 LB | Connection management is stateless, Agents reconnect automatically |
| Consumer | xN replicas + Kafka ConsumerGroup A | Automatic Partition rebalance (RoundRobin strategy) |
| Engine | xN replicas + Kafka ConsumerGroup B | Offsets independent of Consumer |
| LLMProxy | xN replicas + stateless HTTP | Shared Redis cache + blacklist |
| VulnSync | xN replicas + Leader Election | With redsync only one replica actually fetches; the rest are hot standbys |
| Kafka | 3-broker KRaft cluster | replication_factor=2 |
| Redis SD | Pub/Sub multi-replica sync + 30s full fallback | Manager memory is the source of truth; Redis is the sync cache across instances |

### To be built separately for production

| Component | Recommended approach |
|------|---------|
| MySQL | Primary-replica replication / MGR / cloud RDS |
| Redis | Sentinel / managed cloud Redis |
| ClickHouse | Replicated tables / cloud ClickHouse (currently a single instance; data has a TTL and can be replayed from Kafka if lost) |

### Distributed locks

Mutual exclusion locks are implemented with Redis SetArgs{Mode: "NX"}:

| Lock purpose | Scheduling interval | Lock TTL | Key |
|--------|---------|--------|-----|
| Task scheduling | 5s | 8s | `mxcwpp:task:dispatch:lock` |
| Virus database update | 4h | 10m | `mxcwpp:virusdb:update:lock` |

When Redis is unavailable it falls back to lock-free mode, relying on the natural staggering of scheduling intervals to reduce the chance of conflicts.

### Thundering-herd protection

`singleflight.Group` ensures that when the cache expires only one goroutine starts the backend computation, and the other goroutines share the same result. Use cases include:

- Dashboard statistics computation (`mxcwpp:cache:dashboard:stats`, TTL 30s)
- Host monitoring metric aggregation (`mxcwpp:cache:monitor:host:{range}`, TTL 60s-10m)

### Task dispatch reliability

- All tasks are first persisted to MySQL (status=pending)
- Manager looks up SD + Redis to route and dispatch to the target AC
- When the Agent is offline or the AC is unreachable, the task stays pending
- When Consumer consumes heartbeats it checks pending tasks and triggers re-dispatch
- Task scheduling uses a Redis distributed lock to avoid duplicate dispatch by multiple replicas

## Security and communication

| Link | Protocol | Authentication |
|------|------|---------|
| Browser <-> Nginx / Manager | HTTPS / REST | JWT |
| Agent <-> AgentCenter | gRPC bidirectional stream | mTLS (VerifyClientCertIfGiven) |
| Agent <-> Plugin | OS Pipe + Protobuf | Parent-child process isolation |
| Manager <-> AgentCenter | Internal HTTP interface | `X-Internal-Secret` shared secret (constant-time comparison) |

**mTLS details**: AgentCenter's TLS configuration uses the `VerifyClientCertIfGiven` policy. A single listening port cannot set `ClientAuth` separately for enroll and normal streams, so it combines "allow at TLS + enforce at the application layer": connections without a client certificate can only use the enroll phase of Transfer, and all other RPCs require a verified client certificate, enforced by an interceptor.

**gRPC Keepalive**: Time=60s (send a ping after being idle), Timeout=10s (timeout waiting for the ping response), MinTime=10s (minimum client ping interval).

Certificate generation: `scripts/generate-certs.sh`

### AgentCenter management port authentication and network boundary

The AC HTTP management port carries high-risk interfaces. Threat model and access control:

| Interface | Authentication | Notes |
|------|------|------|
| `/command` `/command/batch` `/dependency/install` `/plugins/resend` | Mandatory `X-Internal-Secret` (`internal_secret`) | Called by Manager; can dispatch tasks to Agents; without credentials returns 401 and the handler does not run |
| `/command/raw` | Mandatory `X-Internal-Secret` (`ac_admin_secret`) | Forwards complete commands between instances (including upgrades and plugin configuration); does not accept `internal_secret` |
| `/admin/drain` `/admin/undrain` | Mandatory `X-Internal-Secret` (`ac_admin_secret`) | Disconnects all agent connections on this instance; does not accept `internal_secret` |
| `/conn/stat` `/conn/list` | Mandatory `X-Internal-Secret` | Leaks the list of online Agents, so protected the same way |
| `/health` | Anonymous | Minimal liveness only (`{"status":"ok"}`), no online details; used by Manager SD for liveness probing |
| `/ready` | Anonymous | Returns only whether the instance is draining, for readiness checks by the front proxy |
| `/metrics` | Anonymous | Prometheus scraping; the deployment topology ensures it is reachable only from controlled networks and is not published to the host's public network |

- The shared logic is in the neutral package `internal/server/common/internalauth` (shared by Manager and AC; both the provided value and the secret are normalized with SHA-256 to fixed-length digests before `subtle.ConstantTimeCompare`, avoiding a length side channel; an empty secret fails closed and always rejects; the secret is never logged).
- On the Manager side, command dispatch / dependency installation (`sd.ACDispatcher`) carries the same secret for both precise routing and broadcast.
- Manager's internal service routes `/api/v1/internal/ac/*` and `/api/v1/internal/alerts/*` **always mount** `internalauth.Middleware`; with an empty secret the middleware fails closed and returns 401, so they are never reachable anonymously.
- **Fail fast at startup (no silent half-broken state)**:
  - AgentCenter: `Config.ValidateAgentCenter()`, via `ValidateInternalSecret`, **regardless of the bind address** requires `server.internal_secret` to be non-empty, not a template placeholder, not a weak default and at least 32 characters long. With an empty secret all protected AC interfaces return 401 and registration/command dispatch fail permanently, so even on loopback it refuses to start with an empty secret; on non-loopback it additionally stresses the risk of an exposed management plane.
  - Manager: `Config.ValidateManager()` strictly validates the same secret before opening the internal routes and exits on failure (called only on the Manager-specific initialization path, so it does not affect Consumer/Engine and other processes that share Config).
  - Cluster deployment (`internal/deploy/cluster`) strictly validates `app.internal_secret` in `Config.Validate()`, and Manager and all ACs are rendered with the same secret.
- **Manager and AC must be configured with the same `server.internal_secret`** (including local development; otherwise AC↔Manager registration and command dispatch are blocked with 401).
- Secret source: `server.internal_secret` (deploy.sh generates it from `INTERNAL_SECRET` in `.env` and idempotently persists it as a single line; clusters render it from `app.internal_secret`).

### Single-tenant consolidation

The product is positioned as a **single-tenant** Linux/K8s CWPP. The multi-tenant/managed-service product surface that once existed has been removed:

| Removed | Notes |
|---|---|
| `biz/billing`, `biz/federation` | Both were dead code with zero external references when removed |
| `biz/mssp` + `/api/v2/mssp/*` | MSSP cross-tenant console, part of the managed-service product line |
| `/api/v2/admin/tenants/*` | Tenant CRUD, disable/restore, per-tenant switching of the run mode |

14 routes were removed in total. The run mode query `/api/v2/system/mode` is kept, but **no longer switches per tenant**:
the mode is a deployment-level setting.

**The underlying `tenant_id` is deliberately kept**: all 262 filter points pass the default tenant `t-default`. Dropping the column would be a high-risk
data migration whose only benefit is one fewer field; what was consolidated is the product surface, not the data model. If multi-tenancy is ever really needed,
the data side will not have to start from scratch.

`internal/server/manager/router/single_tenant_test.go` guards this boundary: it fails if multi-tenant routes or removed packages reappear.

### Incident operations loop

Previously incidents had only the three states `active/investigating/resolved` and a `resolved_by` field (which in practice was only ever written as
`auto`): **no owner, no response deadline, no triage verdict, and closing required no reason**.
No matter how accurate detection is, what it produced was just alerts that piled up until nobody looked at them; the ability to find problems never turned into the ability to handle them.

The loop is built on the existing `Incident` rather than a separate parallel Case table: correlation logic, risk aggregation and member alerts
are all already there, and two tables would only produce two sets of facts that drift out of sync.

| Step | Semantics |
|---|---|
| Assign / claim | Recorded separately. **Being assigned does not mean someone has started looking**; conflating them would distort MTTA. Re-claiming does not refresh the time; MTTA records the first person who actually started looking |
| SLA | When an incident is created, claim and resolve deadlines are computed from its severity. A one-size-fits-all deadline either wears people out on low severity or buries high severity; an unknown severity falls back to the most lenient, so a typo does not wake anyone up |
| Triage | Closing **must** give `true_positive` / `false_positive` / `benign_true_positive` |
| Escalation | Must state the target and reason, otherwise "escalated" cannot be traced afterwards |
| Close | **Must state a reason**, and records the actual operator |

The single `incident_events` table carries state changes, triage notes and evidence references. It is not split into three tables for comments/audit/evidence:
the investigation itself is one continuous narrative, and once split, "who made which decision, when, and based on what" has to be stitched together across tables,
which is exactly the only thing a post-mortem needs to see. State changes and timeline records are written in the same transaction: a state that changed without a record
means nobody can later explain who made that decision.

**Giving `benign_true_positive` its own category** is key: detection was correct but the behavior was harmless (for example, ops' own operations);
counting it as a false positive would cause rules to be wrongly loosened.

Triage verdicts are also the only trustworthy source of detection quality: precision can only be computed from them. Using the count of `resolved` instead
would count "nobody looked, so they were bulk-closed" as detection accuracy.

### Manual response and a hard ban on automated actions

Isolating a host cuts off business traffic. The original implementation **took effect immediately with a single API call**: no second person had looked at it,
there was no idempotency key, no rollback record, and afterwards nobody could answer "why was this machine isolated at the time, and who approved it".

Response actions now go through a full lifecycle: `pending → approved/rejected → executed/failed → rolled_back`.

| Constraint | Rationale |
|---|---|
| **Cannot execute without approval** | The check is implemented as `ResponseAction.Executable()` rather than scattered across callers, so a new execution entry point cannot "forget to check approval" |
| **Requesters cannot approve their own requests** | If the same person both requests and approves, approval is just one more mouse click |
| **Unique index on the idempotency key** | The consequences of executing an action twice are asymmetric: an extra isolation may cut off business that had already recovered. The database blocks concurrent duplicates, rather than relying only on a check before submission |
| **Failed vs. not executed are distinguished** | The former needs someone to investigate why it did not take effect; the latter just has not had its turn yet |
| **Rejections must state a reason** | Otherwise the requester does not know what to change |

**The hard ban on automated actions is enforced** at the request entry point: `system` / `auto` / `scheduler` / empty identities are always rejected.
Relying on "there is currently no automated path" holds by coincidence, not by design: `ShouldEnforce` appears only where the pipeline fills fields
and in the unwired admission; any future automation that tries to invoke a response action will fail at this gate
instead of quietly succeeding.

The entire response process flows back as evidence onto the incident timeline, with idempotency keys for traceability: a post-mortem should be able to follow a single timeline
through "detection → triage → request → approval → execution", rather than stitching it together from another page.

### On-call schedule and response deadlines

The incident loop added claim and resolve deadlines, but **nothing read them**: a deadline nobody looks at is just a column
of data, the same problem as "instrumented but nobody alerts on it". Both sides are now filled in:

**On-call schedule**: `oncall_shifts` schedules by time window, in three tiers `l1 / l2 / security`.
When a new incident is created it is automatically assigned to the first-line person on shift. Without automatic assignment, incidents default to having no owner,
and timeout alerts would just fire every day with nobody knowing whom to contact.

Scheduling is by time window rather than by fixed person: on-call rotates, and hard-coding the owner in configuration means every shift change requires a configuration change.
When several people are on in the same period, the one whose shift started earliest is chosen: "everyone is on shift" equals "nobody is responsible".

**No one on call is not silently skipped**: a timeline record is left. A scheduling gap is itself a problem operations must handle,
and hiding it only leaves the incident ownerless. An assignment failure also does not prevent the incident from being persisted: binding creation and assignment together
would turn a scheduling gap into "the incident is gone too".

**Escalation moves up the tiers**, with the target computed from the on-call schedule rather than filled in by hand: making someone figure out "whom to escalate to" by themselves at three in the morning
does not work. At the top tier it reports an explicit error instead of pretending the escalation succeeded.

**Timeout detection** runs every 2 minutes and only observes without changing state: automatically marking timed-out incidents with some other state would hide the problem;
what a timeout should do is let people know, not make it disappear from the to-do list. The metrics are Gauges rather than Counters:
what operations needs to ask is "how many are unattended right now", not "how many times did something time out historically".

| Metric | Meaning |
|---|---|
| `mxcwpp_incident_sla_breached{kind,severity}` | Number of incidents currently past their claim/resolve deadline |
| `mxcwpp_incident_unowned` | Number of open incidents without an owner (a precursor to timeouts) |

To the customer, an unclaimed high-severity incident and an undetected attack have the same outcome.

### Single egress exit

`biz/outbound` contained 9 connectors (Splunk HEC, QRadar LEEF, Elastic, Alibaba Cloud SLS, etc.),
**all with zero external references**; `SetSIEMForwarder` was only defined, with zero calls. Consumer did construct a
Forwarder and log "SIEM forwarder started", and then **never called it**: the logs said it was running,
but not a single alert could actually be sent. "Integrates with your existing SIEM" was not true before.

Now only one exit remains: **CEF over Syslog** (`siem` configuration section, disabled by default). The 9 dead connectors have been removed.

**Egress and notification are two different things**, which determines where egress sits in the pipeline:

| | Notification | Egress |
|---|---|---|
| Purpose | Wake people up | Hand the record to the customer's logging system |
| Category staged rollout | Restricted | **Not restricted** |
| Severity threshold | Restricted | **Not restricted** |
| Suppression window | Restricted | **Not restricted** |

Suppression exists to disturb people less, not to make the customer's SIEM receive fewer records. If egress were also suppressed, the customer side would have
gaps created unilaterally by the platform, with no way of knowing what was missing. Egress therefore happens **before** all notification thresholds.

**All alert sources are covered**. The alerts table path (CEL/Sequence/IOC + Stage alerts) has its own notification,
so it is marked `EgressOnly` when wired in: egress only, no duplicate notification. Exporting only part of the alerts is more dangerous than exporting none: the customer would think
they had received everything.

**Bounded asynchrony**. The underlying `SendAlert` writes to the socket while holding a lock, with a 5-second timeout; the original CEL path started one
goroutine per alert to contend for the same lock, which under an alert storm would pile up large numbers of blocked goroutines. Everything now goes through a bounded queue;
when full, alerts are dropped and counted in `mxcwpp_alert_egress_total{outcome="dropped_queue_full"}`:
better for egress to miss entries than to slow down detection, but drops must be visible.

### Compound result states for malicious file scanning

When the ClamAV / YARA engine was unavailable (not installed, out of memory) or failed during execution, the scanner used to return
`(nil, nil)`: the caller read "zero threats, no error", and the task reported `status=completed`,
`threat_count=0`. **A host that did not even have ClamAV installed was reported by the platform as having no malicious files.**

Now each engine produces an execution receipt (`scanned` / `unavailable` / `failed`), and the overall verdict is derived from the receipts:

| Verdict | Meaning |
|---|---|
| `clean` | All engines ran and no threats were found |
| `infected` | Threats were found (even if another engine failed to run, a confirmed threat is not downgraded) |
| `partial` | Some engines did not run or failed; coverage is incomplete and **insufficient to conclude the host is clean** |
| `unavailable` | No engine was available; no scan actually happened this time |

The task completion signal carries `scan_status` and per-engine receipts; the server counts hosts with incomplete coverage in
`antivirus_scan_tasks.degraded_hosts`, and a non-zero value means "the task shows as fully scanned, but these hosts were not scanned".

**Not scanned is a coverage gap, not a verdict**: this is the same class of problem as "a failed request rendered as 0":
showing "don't know" as "no problem".

### Observability and alert coverage

The platform's typical pattern used to be "instrumented, but nobody alerts": the three metrics for agent dropped events, engine backpressure drops and Stage errors
were being collected all along and visible on charts, but no rule would ever wake anyone up. Data being lost without anyone knowing
is no different from not having these metrics at all.

Key metrics must have corresponding alerts; `internal/deploy/alertcoverage_test.go` pins the list,
and adding a key metric without a matching rule fails:

| Metric | Meaning |
|---|---|
| `mxcwpp_agent_event_dropped_total` | Agent dropping events = detection blind spot on that host |
| `mxcwpp_engine_backpressure_drop_total` | Engine backpressure drops = missed detections |
| `mxcwpp_engine_stage_errors_total` | Persistent Stage errors = that capability silently failing |
| `mxcwpp_consumer_dlq_write_failures_total` | DLQ write failures = messages irrecoverably lost |
| `mxcwpp_consumer_ch_write_errors_total` | CH write failures = offset advancement paused |
| `mxcwpp_ac_unrouted_datatype_total` | DataType with no registered route = messages silently ignored |
| `mxcwpp_ac_stream_idle_closed_total` | Agent connected but not sending = detection blind spot on that host (AgentCenter closes the stream and forces a reconnect after 3 heartbeat periods without messages) |
| `mxcwpp_vulnsync_last_success_timestamp_seconds` | Vulnerability database stopped updating = the UI is showing stale data |

Vulnerability database freshness deliberately measures "how long since the last success" rather than "how many runs": the latter keeps
growing when the job fails repeatedly, and only the former answers "until when can I trust the vulnerability data I am looking at". A failed sync **does not update**
the timestamp; otherwise the alert would never fire when updates stop.

### Runtime capability list

The code had 19 detection Stage constructors, but only 8 were actually wired into the pipeline; of those wired in, 3 sent
alerts to `mxcwpp.engine.alert`, and that topic **had no consumers at all**: even when running, nothing reached the UI.
Between "the code exists" and "the capability is running" there were two gaps, and previously they could only be told apart by manual grep, with numbers that did not agree with each other.

`internal/server/engine/capability.go` is the authoritative list, assigning each capability to one of three tiers:

| Tier | Meaning | May be claimed externally? |
|---|---|---|
| `active` | Wired, and alerts actually go somewhere | ✅ |
| `dead_end` | Wired, but nobody consumes the alerts | ❌ Must state what is missing |

| `unwired` | Has a constructor but was never wired | ❌ |

The list is published as JSON via `GET /capabilities` (Engine HTTP) for operations and delivery processes to check against.

The gate `capability_test.go` (`make test`) compares the list against the real code in both directions: a new constructor that is not registered, a declared-wired entry
whose entry point is not wired, and a declared-unwired entry that is actually wired all fail. `dead_end` entries must state the reason, and once
`engine.alert` gains a consumer, the test prompts to change the status back to `active`, so that nobody fixes it and forgets to update the list.

**External claims follow the list**: only capabilities in the `active` tier may appear in proposals, the official website or POCs.

### Signal persistence

engine sends **every** detection hit (including low-fidelity and observation-stage ones that do not raise alerts on their own) to `mxcwpp.engine.alert`,
with `stage` in the message (cel_rule / sequence / rootkit ...). consumer consumes it with a separate consumer group `mxcwpp-consumer-signals`,
merges by "host + stage + rule + program + 10 minutes" and writes to the ClickHouse `signals` table (retained 30 days),
with `rule_id` converted to the form used in the alerts table (`cel-N` / `seq-N`).

- The offset is committed only after writing to ClickHouse; on write failure the merged results stay in memory for retry, and consumption pauses when memory is full (200,000 keys);
- A new consumer group, and a committed position deleted by the topic's retention period, both resume from the earliest position, so backlog is never silently skipped;
- A single host may occupy at most 2000 keys per flush cycle (program paths come from host reports and can be flooded); hits beyond that are counted under `(overflow)`, so counts are not lost;
- Separate from the main consumer group: the speed and failures of the signal path do not affect event persistence or alerting;
- Command lines have passwords masked before persistence, the same as in alert details;
- The same key may have multiple rows in one time bucket (each flush writes one increment); aggregate with `sum(hits)` by key.

Purpose: a single weak signal is no longer "neither alerted nor recorded"; it can be queried and counted, and serves as input to risk accumulation and prevalence statistics.

A rule's fidelity (whether it raises alerts on its own) is determined only by the built-in rule files, synced when manager starts; rules users have modified in the console are not overwritten.
Migrations no longer change fidelity by category: doing so would fight with the sync, and rules would flip back and forth between "alert" and "silent" depending on the restart order of the services.
Alerts: write failures, backlog reaching its limit, no output for 15 minutes, consumer lag, large numbers of unparseable hits, and send failures on the engine side
(`MxCwppConsumerSignals*`, `MxCwppEngineAlertPublishFailing`).

Hits sent before engine was upgraded have no `stage` field; in rows backfilled from them `stage` is empty and CEL and attack chain rule numbers cannot be distinguished, so exclude them from statistics.

The signals table has no readers yet: until risk accumulation goes live, hits from low-fidelity rules are only "queryable" and will not wake anyone up.

### Entity risk accumulation (shadow phase)

engine feeds every hit in the pipeline (including intelligence hits; excluding shadow rules, unregistered hosts and hits whose tactic cannot be inferred) to the risk accumulator
(`internal/server/engine/risk`), **counting it toward two layers of entities at the same time**:

- **Lineage layer**: host + process lineage root. Walks up the process tree and stops at a login session (sshd), a service manager (systemd / pid 1),
  a scheduled job (cron / atd) or a container entry point (containerd-shim / conmon / runc); if the parent chain is broken, the topmost known process is used.
  Each host has at most 500 lineage entities; hits beyond that are counted only at the host layer;
- **Host layer**: the whole host, as a fallback. Lineage can be split apart (spawning each step via cron, ssh loopback or disguised program names), and also breaks when ancestor processes
  predate agent startup or engine restarts; the host layer is unaffected and has stricter thresholds.

Scoring and decisions:

- Within a one-hour window, each ATT&CK tactic takes only its single highest signal (low 1 / medium 3 / high 6 / critical 10), summed across tactics;
  the same rule within the window takes its highest occurrence;
- The tactic declared by the detection stage itself is used; otherwise the primary tactic is inferred from the technique ID; hits whose tactic cannot be inferred do not take a slot;
- **The prevalence coefficient applies only to low-severity signals**: 0.3 for those seen on more than half of registered hosts, 0.7 for 10%–50%. Medium and above are not downgraded for being "common"
  (an attacker can run a payload through an interpreter present across the whole fleet). The coefficient table is no longer used if it has not been updated for more than 3 hours;
- **Effective tactics**: the lineage layer judges by the pre-downgrade weight (a common whoami within the same lineage is still a link in the attack chain; it is only downgraded, not dropped as a tactic),
  the host layer judges by post-downgrade weight ≥ 1 (common low-severity signals are everywhere on a whole machine);
- Lineage layer: 2 effective tactics are recorded as a candidate; 3 with a pre-downgrade score ≥ 6, or a score ≥ 16, are recorded as "would alert".
  Host layer: 3 are recorded as a candidate; 4 with a score ≥ 10, or a score ≥ 24, are recorded as "would alert". A minimum score is required when alerting by tactic count because an administrator's
  everyday session can also reach the count with common low-severity signals. The thresholds are initial values, to be tuned with shadow data;
- An activity lasts at most 6 hours, after which it starts over; when a new medium-or-higher rule appears, an entry is recorded even if the tactics and score did not change, so attack steps within noisy entities become visible;
- Time is taken from the Kafka message time (the moment AC delivered it; when an agent re-sends after a disconnect it still differs from when the event actually happened); times more than 5 minutes ahead of the wall clock are counted as wall-clock time;
  expiry cleanup uses the maximum event time seen for that host (a host's events are in only one partition, and each partition has a different backlog), so a consumer backlog does not wipe out entities;
  entities with no update for 6 hours by wall clock are also cleaned up;
- Inbound hits on intelligence IPs are not counted (a public service being scanned is not outbound C2; when the direction field is missing, the connection type is used to decide);
- Lineage boundary programs must be under system directories; disguises like `/tmp/cron` do not count as boundaries;
- **No allowlist filtering**: allowlists were written to reduce noise for individual alerts; carrying them into combined judgments would also hide attacks that can only be found through combinations;
- Command lines (including those of lineage root processes) have passwords masked before persistence.

`risk.mode` (engine configuration) currently supports only `shadow` and `off`, default `shadow`: decisions are **appended** to MySQL `risk_decisions`
(a new row each time a decision changes, recording both the pre- and post-downgrade scores, so you can later replay "when, and because of which signals, it crossed the line"; retained 30 days,
cleaned in batches by engine every hour), and **no alerts are produced**.
Database writes go through an asynchronous queue; when it is full or a write fails, the write is dropped and counted, the entity reverts to "never written", and the next hit rewrites it. An engine restart loses the in-memory accumulation for the last hour.

Known limitations: lineage is assembled by engine from execution events and is broken by the following cases, with the host layer as the fallback; the real fix must wait until the sensor reports the parent process chain directly.
Events from the same host are processed concurrently, so when a child process arrives before its parent, the parent-child relationship is not filled in; a process that execs in place breaks off its earlier descendants;
when a parent process predates the agent or engine restarts, each command becomes its own root; process tree cleanup (2 hours after the root process exits, 6 hours idle) causes long-running processes to change roots. Scan detection and storylines do not feed into the accumulator
(the former is external inbound scanning present on almost every host; the latter's inputs already enter through CEL rules).

Alerts: `MxCwppEngineRiskPersistDropped`, `MxCwppEngineRiskStalled`, `MxCwppEngineRiskDisabled`, `MxCwppEngineRiskDegraded`,
`MxCwppSignalPrevalenceStale`.

### Single alert persistence path

Every Stage in the pipeline sends its alerts to `mxcwpp.engine.alert`. The only consumer of that topic is signal persistence (see the next section),
which does not produce alerts. CEL / Sequence / IOC show up in the UI because they additionally attach an `AlertGenerator`
and persist on their own; Privilege / RASP / AntiRootkit did not attach one: detection was running, alerts were being sent, and the UI never saw them.

Persistence is now unified in the pipeline: for Stages that do not implement `PersistsOwnAlerts()`, alerts are written via
`StageAlertWriter` into the `alerts` table with `result_id = engine-{ruleID}-{hostID}` (no
timestamp; repeated hits increment `hit_count` instead of adding rows), and a recurring alert that had been handled returns to the active state.

Stages that persist on their own declare it explicitly via `PersistsOwnAlerts()`, and the pipeline skips them accordingly, so the same
hit is not written twice. `AlertGenerator` is not reused because it is tightly coupled to CEL (numeric `rule.ID`,
`cel-%d` result keys, low-fidelity and observation-period decisions that depend on rule fields); synthesizing fake rules for hard-coded Stages
would disguise them as CEL rules and misapply governance semantics that only make sense for CEL.

### Agent identity chain of trust

Agent access trust rests on three stages; if any stage is missing, the connection is rejected fail-closed:

1. **Pin the AC identity on first connection**. When there is no local CA file, the Agent performs full pinned-root verification using the CA fingerprint embedded at build time: the certificate matching the fingerprint must really be a CA, the leaf certificate must verify against that CA, its SAN must match the target hostname, and its usage must include `serverAuth`. "The CA appears in the chain" alone is not enough: an attacker can stuff the public CA certificate into a forged chain. Without a valid fingerprint it **fails before connecting** and does not fall back to unpinned `InsecureSkipVerify`.
2. **Enroll for a per-host certificate**. An Agent without a client certificate can only enroll: it submits a valid AgentID and enroll token (fixed-length digest + constant-time comparison; an empty token is always invalid), AC signs a per-host certificate with `CN=AgentID` on the spot, delivers it, and then ends that stream. During enrollment no connection is registered, no heartbeats are processed and no plugin tasks are dispatched.
3. **Mandatory identity binding in steady state**. Certificate-bearing connections must have client certificate CN == the reported AgentID, revoked serial numbers are rejected during the handshake, and all non-Transfer RPCs require a verified client certificate.

Per-host certificates let a compromised host be revoked individually, and a leaked private key does not affect other machines. Installation packages from production builds no longer ship a shared client certificate.

`insecure_dev_mode` is the only relaxation path; it is restricted to being usable only when both gRPC and HTTP bind to loopback, and the official deployment rendering never sets it.

### Execution boundary for dispatched commands

The platform dispatches commands to Agents and runs them as root, so "who can edit content" is equivalent to "who can execute code across the whole fleet". The execution side uniformly uses **structured argv + explicit allow sets**, and no longer uses "dangerous-word blacklist + shell strings":

| Path | Boundary |
|------|------|
| Vulnerability remediation (`plugins/remediation`) | Commands are split into argv and checked item by item against allowed programs / subcommands / options / operands, executed **without a shell**; operands must not be paths, URLs or package files |
| Remote forensics (`internal/agent/forensics`) | Allowlist of read-only forensic programs, likewise argv-based and without a shell; excludes `find` (`-exec`/`-delete` cannot be constrained to read-only), interpreters and download tools |
| Baseline `command_exec` / `fix.command` | Custom rules may not be **newly added** (consistent across the three write entry points: create, update and policy import); **existing** ones are reported or blocked by the dispatch gate depending on configuration; built-in rules are not restricted |

The trust source for baseline rules is the `builtin` flag: it is set only by server-side rule file sync and a one-time migration, and no user request can change it, so it is sufficient to distinguish "official rules distributed with releases" from "user-created rules" without adding another layer of manifest signatures.

Existing custom executable rules are handled in two steps: `GET /api/v1/policies/custom-exec-rules` produces a list for manual review, and only after confirming they can be tightened is `server.security.block_existing_custom_exec_rules` enabled. By default it only records audit entries without blocking: blocking by default would silently reduce existing baseline coverage. The dispatch gate is a **process-level** policy rather than a TaskService instance field: the service has 6 construction sites and most of them cannot get Config, so making it an instance field would plant a fork where "some dispatch path forgets to set it, and the gate silently fails on that path".

Why a prefix allowlist was not used: a prefix constrains only the first word and leaves the argument space completely open, and as long as `sh -c` is still involved, any syntax not enumerated (newline separators, command substitution, redirection) is a gap. The shared validation lives in `internal/common/execpolicy`.

The install operations of `rpm` and `dpkg` accept only file paths, and installing a local package necessarily runs the package's maintainer scripts as root; there is no safe form of operand, so they were removed entirely. Package installation always goes through the package manager, fetching by package name from configured repositories.

### RBAC deny-by-default and route coverage gate

- All JWT-authenticated routes (`apiV1Auth`) go through `EnforcePermissions`: checked by "module × action" (view/manage/respond); **unregistered routes are always rejected for non-admins (deny-by-default) and an `access.denied` audit entry is recorded**, rather than being allowed through because of an empty mapping; admin is an explicit superuser path.
- `/api/v2` management-plane routes (`/admin`, `/config/change-requests`, `/mssp`) have an explicit admin gate; `/system/mode` is a read-only query available to any logged-in user.
- The authoritative route classification table `internal/server/manager/api/route_policy.go` assigns every registered route to one of public / internal / authenticated-perm / authenticated-basic / admin (public/basic use **exact method+path**, not prefix swallowing).
- **Exact route golden manifest**: `internal/server/manager/router/testdata/routes.golden` records `METHOD PATH CLASS PERM` line by line. The test `route_manifest_test.go` compares the **actual `engine.Routes()`** against the golden file in both directions: new unregistered routes, stale entries, and class/permission changes all fail (new routes are not automatically swallowed by a broad prefix). After changing routes, regenerate with `go test ./internal/server/manager/router/ -run TestRouteManifest -update-routes` and have a human review the diff (the test itself does not modify the golden file on its own).
- Runtime gate verification `route_gating_test.go`: sends real credential-less requests to representative routes of each class (internal / authenticated / admin / public) and asserts they are intercepted by the corresponding mechanism before the handler (classification = actual gating).

## Key differences from Elkeid

This project's design draws on Elkeid's Agent + Plugin + Server architecture, but differs in implementation as follows:

| Dimension | Elkeid | MxCwpp |
|------|--------|-------|
| Storage | MongoDB | MySQL + ClickHouse |
| Service discovery | Standalone SD service | SD module embedded in Manager (Registry struct) |
| SD sync | - | Redis Pub/Sub real time + 30s full fallback |
| Kafka Topic | Single Topic | 8 Topics grouped by data characteristics |
| Task distribution | Redis PubSub | Persistence + re-dispatch on heartbeat |
| Load balancing | Least connections | power-of-two-choices |
| Agent->AC mapping | Collected periodically by Manager | Written by Consumer while consuming heartbeats |
| Consumption failure handling | - | DLQ (keeps original message + error + retry count) |

## Key code paths

```
cmd/server/manager/              # Manager entry point
cmd/server/agentcenter/          # AgentCenter entry point
cmd/server/consumer/             # Consumer entry point (persistence only)
cmd/server/engine/               # Engine entry point (detection and analysis)
cmd/server/llmproxy/             # LLMProxy entry point (LLM adapter gateway)
cmd/server/vulnsync/             # VulnSync entry point (vulnerability intelligence fusion)
internal/server/audit/           # Central operation audit recorder (neutral shared: manager + agentcenter each Init)
internal/server/manager/sd/      # AC service discovery and registration (Registry struct)
internal/server/common/kafka/    # Kafka Producer / Topic routing
internal/server/consumer/        # Consumer routing / Writer / DLQ
internal/server/consumer/gcppubsub/     # GCP Pub/Sub consumption (GKE audit logs)
internal/server/engine/          # Engine 16 stages + detection subpackages
internal/server/engine/celengine/       # CEL rule engine + port scan detection
internal/server/engine/intrusion/       # Intrusion detection, 4 major categories
internal/server/engine/microseg/        # Microsegmentation + K8s NetworkPolicy recommendations
internal/server/engine/storyline/       # ATT&CK attack chain timeline
internal/server/engine/ml/              # Go-native IForest (not wired, no ONNX)
internal/server/engine/scheduler/       # IOC/rule/vulnerability intelligence sync scheduling
internal/server/llmproxy/        # LLMProxy: provider / router / cache / quota / audit
internal/server/vulnsync/        # VulnSync: sources / leader / publisher
internal/server/hunting/         # SPL-style DSL → ClickHouse SQL translation
internal/server/database/        # MySQL / Redis / ClickHouse clients
internal/agent/                  # Agent connection / transport / plugin management
internal/agent/updater/          # Agent self-update and remote upgrade
internal/agent/edr/              # Agent built-in EDR submodules (25+ subpackages)
internal/server/agentcenter/scheduler/  # 8 AC schedulers (update/timeout/IOC sync/rule sync) + startup self-check
internal/server/manager/biz/     # Manager business logic (vulnerability sync/LLM integration/SBOM, etc.)
internal/deploy/cluster/         # Cluster deployment engine (underlying mxctl)
internal/common/signing/         # Ed25519 signing/verification
plugins/                         # 12 plugin implementations; lib/ is the shared plugin SDK
cmd/tools/mxctl/                 # Cluster deployment CLI tool
cmd/tools/ch-spill-replay/       # Writes spilled ClickHouse rows back
```
