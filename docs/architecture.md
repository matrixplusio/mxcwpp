# 架构设计

> 最后更新：2026-06-09 | 适用版本：v2.x（六微服务架构）

## 概述

MxCwpp Platform 采用 **Agent + Plugin + 六服务后端** 分层架构。后端拆分为 **Manager / AgentCenter / Consumer / Engine / LLMProxy / VulnSync** 六个独立服务，每个服务独立部署、独立扩缩容。控制面无状态，支持多实例水平扩展；数据面通过 Kafka 异步解耦，按存储特征分层写入 MySQL（业务主数据）和 ClickHouse（时序与事件归档）。

### 六微服务职责一览

| 服务 | 入口 | 职责 |
|------|------|------|
| Manager | `cmd/server/manager/main.go` | HTTP API、控制台后端、任务下发、服务发现注册中心 |
| AgentCenter | `cmd/server/agentcenter/main.go` | Agent gRPC 接入与数据转发，Kafka 生产者 |
| Consumer | `cmd/server/consumer/main.go` | Kafka 持久化（MySQL/ClickHouse），DLQ 处理 |
| Engine | `cmd/server/engine/main.go` | 检测分析引擎：CEL/序列/ML/Storyline/K8s Audit/RASP/Microseg |
| LLMProxy | `cmd/server/llmproxy/main.go` | 多 LLM 厂商适配网关，告警分析/Storyline 总结/NL2Query |
| VulnSync | `cmd/server/vulnsync/main.go` | 11+ 漏洞情报源融合（NVD/OSV/RHSA/CNNVD/EPSS 等） |

## 系统拓扑

```
                         +--------------------------+
                         |      用户 / 浏览器        |
                         +------------+-------------+
                                      | HTTPS
                                      v
                         +--------------------------+
                         |         Nginx            |
                         +------------+-------------+
                       /api/*         |         静态资源
                +---------------------+--------------------+
                v                                          v
      +--------------------+                    +--------------------+
      |     Manager x N    |                    |    Next.js SPA     |
      | REST API / SD 注册 |                    +--------------------+
      +-------+------------+
              |
              |  HTTP 内部调用
              v
      +-------+------------+   +--------------------+   +--------------------+
      |   LLMProxy x N     |   |    Engine x N      |   |   VulnSync x N     |
      | LLM Gateway        |   | 检测分析（16 stage）|   | 漏洞情报融合        |
      +--------------------+   +-------+------------+   +-------+------------+
                                       ^                        |
                                       | Kafka mxcwpp.agent.*    | Kafka mxcwpp.vuln.advisory
                                       |                        v
      +--------------------+   +-------+------------+   +--------------------+
      |   AgentCenter x N  |--→| Kafka (KRaft x 3)  |←--|   Consumer x N     |
      | gRPC 接入 / 转发   |   | 8 业务 Topic + DLQ |   | MySQL/ClickHouse   |
      +---------+----------+   +--------------------+   +--------------------+
                | gRPC BiDi Stream / mTLS
                v
      +------------------------------------------------------+
      |               mxcwpp-agent（每台目标主机）              |
      |  插件基座 + 生命周期管理 + 服务发现                    |
      |  baseline / collector / fim / scanner / remediation  |
      |  avscanner / rasp-go / rasp-java/python/php/node     |
      |  EDR/eBPF 运行时检测内置于 agent（含 13 个子模块）    |
      +------------------------------------------------------+

存储层（共享）：MySQL 8 / Redis 7 / ClickHouse 24 / Prometheus
```

## 组件职责

### Manager

管理面 HTTP API 服务，无状态，前置 Nginx 负载均衡。

- 提供 100+ 个 REST API 端点，JWT 认证
- 策略、规则、任务、告警、报告、用户等业务 CRUD
- 漏洞管理：多源漏洞库同步（OSV.dev / NVD / Red Hat）+ 主机漏洞扫描
- LLM 告警辅助分析（`internal/server/manager/biz/llm_assist.go`）
- SBOM 导出（CycloneDX 格式，`internal/server/manager/api/sbom.go`）
- 通知服务：告警通知推送与管理
- 内嵌 AC Registry / SD 模块，负责 AgentCenter 注册、主动健康探测、服务发现
- 任务调度：Redis 分布式锁，5s 调度间隔
- 查询 MySQL / ClickHouse / Redis / Prometheus 聚合前端数据
- 任务下发：查 Redis `agent:ac` 映射精准路由到目标 AC
- Dashboard 统计和监控指标使用 singleflight 防惊群，缓存过期时仅一个 goroutine 发起计算

入口：`cmd/server/manager/main.go`

### AgentCenter

Agent 接入层，核心职责为连接管理与数据转发；同时依赖 MySQL 执行任务分发、策略查询、资产写入等业务操作。

- 维护 Agent gRPC 双向流连接池
- gRPC Keepalive 参数：Time=60s, Timeout=10s, MinTime=10s
- mTLS 支持 VerifyClientCertIfGiven（允许无证书首次连接以完成证书下发）
- 将 Agent 上报数据按 DataType 路由到 Kafka Topic
- Kafka 不可用时使用内存降级队列暂存，恢复后自动重放
- HTTP 管理接口：`/health` `/conn/stat` `/conn/list` `/command` `/command/batch`
- 启动时向 Manager SD 注册（重试 3 次），15s 心跳（包含 ConnCount），优雅注销
- 主机性能指标通过 `/metrics` 暴露给 Prometheus 抓取
- 内置 6 个调度器（`internal/server/agentcenter/scheduler/`）：任务调度、心跳超时检测、告警调度、Agent 更新、插件更新、组件推送超时

入口：`cmd/server/agentcenter/main.go`

### Consumer

Kafka 异步消费服务，**仅负责数据持久化**（v2.0 起检测能力已剥离至 Engine 服务）。

- 订阅 8 个业务 Topic（ConsumerGroup A "mxcwpp-consumer"），按 DataType 路由写入 MySQL / ClickHouse
- 幂等写入：MySQL `ON DUPLICATE KEY UPDATE`（逐条 Upsert），ClickHouse `ReplacingMergeTree`
- 批量优化：ClickHouse 5000 条/10s
- 写入失败进 Dead Letter Queue（`{sourceTopic}.dlq` Topic）
- DLQ 消息保留原始消息体、错误信息、重试次数、失败时间
- 不论成功失败均标记 offset，失败消息走 DLQ 而非重试阻塞
- Kafka ConsumerGroup 配置：RoundRobin rebalance 策略，OffsetNewest
- 消费心跳时维护 Redis `agent:ac:{agentID}` 映射，检查 pending 任务触发补发
- GCP Pub/Sub 消费（`internal/server/consumer/gcppubsub/`）：从 Cloud Logging 接收 GKE 审计日志

入口：`cmd/server/consumer/main.go`

### Engine

v2.0 新增的检测分析引擎，独立服务，与 Consumer 并行消费 Kafka。

- 订阅 `mxcwpp.agent.*` 全部业务 Topic（ConsumerGroup B "mxcwpp-engine"），与 Consumer 互不影响 offset
- **16 个检测 Stage**（`internal/server/engine/stage_*.go`）：CEL / Sequence / Anomaly / ML / Audit / Honeypot / Intrusion / Kube / Privilege / RASP / Anti-Rootkit / Rootkit / Storyline / Webshell / Revshell+Priv / AbnormalLogin
- 多层检测子包：
  - `celengine/` — CEL 规则引擎，eBPF 事件实时匹配 + 自动响应触发
  - `intrusion/` — 入侵检测合集（abnormal_login / reverse_shell / rootkit / webshell）
  - `adaudit/` — AD/LDAP 域控审计 7 条规则（DCSync / Kerberoasting / 暴破等）
  - `microseg/` — 微隔离流量识别 + 策略生成 + Kubernetes NetworkPolicy 推荐
  - `kube/` — K8s Audit Event 检测（PSS 等）
  - `rasp/` — RASP 事件汇聚（Java / Python / PHP / Node / Go）
  - `honeypot/` — 反勒索 / 蜜罐告警归并
  - `ml/` — ONNX Runtime CPU 推理（IForest 等）
  - `anomaly/` — 行为基线异常检测
  - `storyline/` — ATT&CK 攻击链关联与时间线
  - `ruleimport/` / `rulesync/` — Sigma/Falco/Tetragon 规则导入与同步
  - `scheduler/` — IOC 同步、规则同步、漏洞情报同步等调度器
  - `rollout/` — 规则灰度发布
- 产出：`mxcwpp.engine.alert` / `mxcwpp.engine.storyline` / `mxcwpp.engine.feedback`

入口：`cmd/server/engine/main.go`

### LLMProxy

v2.0 新增的多 LLM 厂商适配网关，提供统一 Provider 抽象。

- **7 种 Provider**：OpenAI / Anthropic / Gemini / DashScope / DeepSeek / Ollama / vLLM
- **4 种场景路由**：alert_explain（告警解读）/ storyline_summary（攻击链总结）/ nl2query（自然语言转查询）/ rule_draft（规则起草）
- Redis 24h 缓存：入参 SHA256 → 响应映射，命中直接返回
- 主厂商失败自动 Fallback：连续 3 次失败黑名单 5min
- 租户级 token 上限 + 月度成本（USD）告警
- 审计：所有调用入 Kafka `mxcwpp.llm.audit`

入口：`cmd/server/llmproxy/main.go`

### VulnSync

v2.0 新增的漏洞情报融合服务，定时拉取 OS 厂商权威 advisory。

- **OS advisory 源**：RHSA / Rocky / USN / Debian / Alpine / CentOS + 信创 4 源（产 NEVRA + fixed_version + OS gate 的可匹配 advisory）
- 每条 advisory 经 `advisory.AdvisoryMessage` 推送到 Kafka `mxcwpp.vuln.advisory`
- **Manager consumer**（ConsumerGroup `mxcwpp-manager-vulnadvisory`）消费 → `advisory.Matcher` 比对主机软件清单 → 写 `host_vulnerabilities`（与 advisory 同一 `IngestAdvisories` 写路径）
- `POST /sync` 手动触发立即拉取；Leader Election（redsync）避免多副本重复抓取
- Manager 端仍保留：OSV/语言包（PURL 驱动 `SyncByPURLs`）+ NVD/MITRE/CNNVD/KEV/EPSS 元数据 enrich（非时间增量，不归 VulnSync）

> 注：Engine 对 `mxcwpp.vuln.advisory` 的 consumer 当前为 noop 占位；关联检测由后续 PR 引入。
> NVD/KEV/EPSS 等元数据融合（3 级 confidence 仲裁）为后续工作，当前 VulnSync 聚焦 OS advisory 匹配路径。

入口：`cmd/server/vulnsync/main.go`｜迁移记录：`docs/vulnsync-migration.md`

### Agent

部署在目标主机上的轻量守护进程，自身不提供安全能力，所有能力通过插件实现。

- 插件生命周期管理（启动、停止、升级、崩溃重启、watchdog 健康检查）
- gRPC 双向流通信（mTLS），环形缓冲区 2048 条 + 100ms 批量发送 + Snappy 压缩
- 服务发现：查 Manager SD 接口获取健康 AC 列表，power-of-two-choices 负载均衡
- 首次接入允许跳过证书校验以获取证书，后续连接切换为正式 mTLS
- 数据透传，不解析插件内容

入口：`cmd/agent/main.go`

### 插件

每个插件是独立子进程，通过 `os.Pipe` + Protobuf 与 Agent 通信。

| 插件 | 功能 | 触发方式 |
|------|------|---------|
| baseline | 基线检查 + 自动修复（9 种检查器） | 任务下发 / 定时 |
| collector | 资产采集（11 种采集器） | 定时（1-12h） |
| fim | 文件完整性监控（仅 VM） | 任务下发 |
| scanner | 病毒查杀（ClamAV + YARA-X）+ 隔离箱 | 任务下发 / 定时 |
| avscanner | 独立 AV 扫描引擎（按需扫描 / 实时扫描） | 任务下发 / 文件事件 |
| remediation | 漏洞修复执行（支持 dry-run） | 任务下发 |
| rasp-go | Go 应用 RASP 探针 | 应用注入 |
| rasp-java | Java JVMTI Agent | -javaagent 注入 |
| rasp-python | Python sys.settrace hook | import hook |
| rasp-php | PHP Zend extension | php.ini 加载 |
| rasp-node | Node.js inspector hook | --require 注入 |

EDR/eBPF 运行时事件采集（原 sensor/tetragon plugin）已**内置于 agent**，不再独立 plugin。

Agent 内置 EDR 子模块（`internal/agent/edr/`）：

| 子模块 | 能力 |
|---|---|
| collector | eBPF + Tetragon 进程 / 文件 / 网络事件采集 |
| rootkit | DKOM 隐藏 PID / 内核模块 / 端口 / LD_PRELOAD / /proc 不一致扫描 (C2) |
| honeypot | SSH / HTTP 假回应蜜罐 (C1) |
| canary | 反勒索 / 反横移诱饵文件 (B9) |
| forensics | 内存威胁取证 (memfd_exec / process hollowing / shellcode / LSASS dump) (EDR-3) |
| memfd | memfd_create 内存马检测 |
| bde | Boot Disk / 文件系统加密检测（反勒索） |
| npatch | eBPF cgroup_skb (4.10+) + AF_PACKET v3 (CentOS 7 fallback) 热补丁 |
| lsm | LSM bpf 钩子 |
| fanotify | fanotify 文件事件订阅 |
| container | 容器逃逸检测 |
| elfparse | ELF 二进制解析（恶意代码识别） |
| weakpass | 弱口令检测 |
| ioc | IOC 命中匹配 |
| storyline | 本地攻击链聚合 |
| rule | 本地规则引擎（CEL 子集） |
| event | 事件总线 |
| aggregator | 事件聚合 |
| antidebug | Agent 自身反调试 |
| selfprotect | Agent 自保护 |
| isolate | 隔离动作执行 |
| quarantine | 文件隔离箱 |
| av | ClamAV 守护进程接入 |
| rasp | RASP 事件接收端（与 rasp-* plugin 配合） |
| yara | YARA-X 预编译规则匹配 (73 规则 / 50 家族) |

引擎层 `internal/server/engine/` 见上文 [Engine](#engine) 章节。

插件共享库 `plugins/lib/go/` 提供插件与 Agent 通信的标准接口。

## 数据链路

### 上报链路（Agent -> 存储 + 检测）

```
Plugin --> Agent Ring Buffer --> gRPC(mTLS) --> AgentCenter
    --> Kafka(按 DataType 路由到 Topic)
    ├── ConsumerGroup A "mxcwpp-consumer" --> MySQL / ClickHouse / Redis（持久化）
    └── ConsumerGroup B "mxcwpp-engine"  --> 16 Stage 流水线（检测）
                                            --> mxcwpp.engine.alert/storyline/feedback
                                            --> Consumer 持久化告警 + 攻击链
```

Engine 与 Consumer 使用不同 ConsumerGroup，**offset 独立**，任一方异常不影响另一方。

### 下发链路（用户 -> Agent）

```
用户/API --> Manager --> 查 SD + Redis(agent:ac) --> 调用目标 AC HTTP 接口
    --> AC gRPC 下发 --> Agent --> 路由到对应插件执行
```

### 查询链路（前端 -> 存储）

| 查询场景 | 数据源 |
|---------|--------|
| 主机/策略/任务/告警状态 | MySQL |
| 监控指标曲线/趋势图 | Prometheus |
| FIM 事件列表/统计 | ClickHouse（优先），MySQL（fallback） |
| 基线评分 | Redis 缓存 |
| Dashboard 趋势 | ClickHouse 物化视图 |

## Kafka 设计

按数据写入特征分组，各 Topic 独立 Retention 和 Partition 策略：

| Topic | DataType | Partitions | Retention | 说明 |
|-------|----------|-----------|-----------|------|
| `mxcwpp.agent.heartbeat` | 1000, 1001 | 6 | 24h | 心跳/插件状态 -> MySQL |
| `mxcwpp.agent.events` | 6001, 6002 | 12 | 72h | FIM 文件完整性事件 -> ClickHouse |
| `mxcwpp.agent.baseline` | 8000-8004 | 6 | 7d | 基线结果/任务完成 -> MySQL |
| `mxcwpp.agent.asset` | 5050-5060 | 6 | 7d | 资产数据 -> MySQL |
| `mxcwpp.agent.scanner` | 7000-7004 | 6 | 7d | 病毒扫描结果 -> MySQL |
| `mxcwpp.agent.ebpf` | 3000-3002 | 12 | 3d | eBPF 运行时事件 -> ClickHouse |
| `mxcwpp.agent.remediation` | 9100-9299 | 6 | 7d | 漏洞修复任务结果 -> MySQL |
| `mxcwpp.agent.command-ack` | 9999 | 6 | 7d | Agent 命令执行结果 |

> **DataType 分配详情**: 完整的 DataType 分配表、路由映射和新增检查清单见 [docs/datatype-allocation.md](datatype-allocation.md)。
> **注意**: 6004 (FIM 基线快照) 在 AC 侧直接处理，不走 Kafka；9000/9001 为插件 SDK 内部心跳，禁止业务使用。

Partition Key 为 AgentID，保证同一 Agent 数据有序。Replication Factor = 2，`min.insync.replicas = 1`。

各 Topic 配套 DLQ：`mxcwpp.agent.{topic-name}.dlq`。DLQ 消息结构包含原始消息体、错误描述、已重试次数和失败时间戳，便于事后排查和重放。

## 存储分层

| 存储 | 定位 | 写入方 |
|------|------|--------|
| MySQL 8.0+ | 业务主数据（主机、策略、任务、告警状态、资产快照、用户） | Consumer / Manager |
| ClickHouse | 时序分析与事件归档（指标趋势、FIM、告警时间线、审计日志） | Consumer |
| Redis | SD 同步、`agent:ac` 映射、分布式锁、基线评分缓存、防惊群 | Manager / Consumer |
| Prometheus | 主机性能指标查询源（CPU / 内存 / 磁盘 / 网络） | AgentCenter Exporter |

## Redis 缓存设计

Redis 在本系统中承担服务发现同步、路由映射、分布式锁、业务缓存等多项职责。以下为各 Key 模式的完整说明：

| Key 模式 | TTL | 用途 |
|---------|-----|------|
| `ac:instances` (Hash) | 120s | AC 实例注册表。field 为 instanceID，value 为 JSON 序列化的 ACInstance 结构 |
| `ac:sd:changed` (Pub/Sub) | - | AC 状态变更通知频道，多 Manager 副本间实时同步 SD 变更 |
| `agent:ac:{agentID}` | 180s | Agent 到 AC 实例的映射关系，用于任务下发时精准路由 |
| `baseline:score:{hostID}` | 可配置 | 基线评分缓存，避免重复计算 |
| `mxcwpp:cache:dashboard:stats` | 30s | Dashboard 统计数据缓存，配合 singleflight 防惊群 |
| `mxcwpp:cache:monitor:host:{range}` | 60s-10m | 主机监控指标缓存，按时间范围不同设置不同 TTL |
| `mxcwpp:seq:{ruleID}:{hostID}` | rule.Window | 序列检测中间状态，TTL 跟随规则的时间窗口 |
| `mxcwpp:task:dispatch:lock` | 8s | 任务调度分布式锁 |
| `mxcwpp:virusdb:update:lock` | 10m | 病毒库更新分布式锁 |
| `mxcwpp:ioc:{type}` (Set) | 24h | 威胁情报 IOC 集合 |
| `scan:ports:{hostID}:{remoteAddr}` (SortedSet) | 60s | 端口扫描检测滑动窗口 |
| `scan:cd:{sourceAddr}` | 300s | 端口扫描告警冷却 |

## 高可用设计

### 服务发现（SD）实现

Manager 内嵌 Registry 结构体管理所有 AgentCenter 实例的生命周期：

**注册与心跳**

- AC 启动时向 Manager SD 模块注册，注册失败自动重试 3 次
- AC 每 15s 发送心跳，心跳中包含当前 ConnCount（连接数）
- 心跳信息写入 Redis Hash：key 为 `ac:instances`，field 为 instanceID，value 为 JSON 序列化的 ACInstance 结构，TTL 120s

**多副本同步**

- 多个 Manager 副本之间通过 Redis Pub/Sub（频道 `ac:sd:changed`）实时同步 SD 变更
- 30s 全量同步兜底，防止 Pub/Sub 消息丢失导致状态不一致

**健康探测**

- 关键参数：probeInterval=10s，probeTimeout=3s，unhealthyThreshold=3 次，heartbeatTTL=60s
- 主动探测方式：HTTP GET `/health`，超时 3s
- 连续 3 次探测失败后标记实例为不健康，从可用列表中摘除

**Agent 路由**

- 任务下发时查询 Redis key `agent:ac:{agentID}`（TTL 180s）精准路由到 Agent 所在的 AC 实例
- 精准路由失败时降级为广播模式，向所有健康 AC 实例发送命令

### 已具备 HA 能力

| 组件 | 方式 | 说明 |
|------|------|------|
| Manager | xN 副本 + Nginx least_conn | 无状态，JWT 认证，Redis 共享缓存 |
| AgentCenter | xN 副本 + L4 LB | 连接管理无状态，Agent 自动重连 |
| Consumer | xN 副本 + Kafka ConsumerGroup A | Partition 自动 Rebalance（RoundRobin 策略） |
| Engine | xN 副本 + Kafka ConsumerGroup B | 与 Consumer 互不影响 offset |
| LLMProxy | xN 副本 + 无状态 HTTP | Redis 共享缓存 + 黑名单 |
| VulnSync | xN 副本 + Leader Election | redsync 仅一个副本实际抓取，其余热备 |
| Kafka | 3 Broker KRaft 集群 | replication_factor=2 |
| Redis SD | Pub/Sub 多副本同步 + 30s 全量兜底 | Manager 内存为源头，Redis 为多实例同步缓存 |

### 需按生产环境独立建设

| 组件 | 推荐方案 |
|------|---------|
| MySQL | 主从复制 / MGR / 云 RDS |
| Redis | Sentinel / 云托管 Redis |
| ClickHouse | 副本表 / 云 ClickHouse（当前单实例，数据有 TTL，丢失可从 Kafka 重放） |

### 分布式锁

通过 Redis SetArgs{Mode: "NX"} 实现互斥锁：

| 锁用途 | 调度间隔 | 锁 TTL | Key |
|--------|---------|--------|-----|
| 任务调度 | 5s | 8s | `mxcwpp:task:dispatch:lock` |
| 病毒库更新 | 4h | 10m | `mxcwpp:virusdb:update:lock` |

Redis 不可用时降级为无锁模式，依赖调度间隔的自然错开来降低冲突概率。

### 防惊群机制

使用 `singleflight.Group` 确保缓存过期时只有一个 goroutine 发起后端计算，其余 goroutine 共享同一结果。应用场景包括：

- Dashboard 统计数据计算（`mxcwpp:cache:dashboard:stats`，TTL 30s）
- 主机监控指标聚合（`mxcwpp:cache:monitor:host:{range}`，TTL 60s-10m）

### 任务下发可靠性

- 所有任务先持久化到 MySQL（status=pending）
- Manager 查 SD + Redis 路由到目标 AC 下发
- Agent 离线或 AC 不可达时任务保持 pending
- Consumer 消费心跳时检查 pending 任务，触发补发
- 任务调度使用 Redis 分布式锁，避免多副本重复分发

## 安全与通信

| 链路 | 协议 | 认证方式 |
|------|------|---------|
| 浏览器 <-> Nginx / Manager | HTTPS / REST | JWT |
| Agent <-> AgentCenter | gRPC 双向流 | mTLS（VerifyClientCertIfGiven） |
| Agent <-> Plugin | OS Pipe + Protobuf | 父子进程隔离 |
| Manager <-> AgentCenter | HTTP 内部接口 | 内网调用 |

**mTLS 细节**：AgentCenter 的 TLS 配置使用 `VerifyClientCertIfGiven` 策略，允许 Agent 首次连接时不携带客户端证书（用于初始证书下发），后续连接切换为完整 mTLS 双向认证。

**gRPC Keepalive**：Time=60s（空闲后发 ping），Timeout=10s（ping 等待响应超时），MinTime=10s（客户端最短 ping 间隔）。

证书生成：`scripts/generate-certs.sh`

## 与 Elkeid 的关键差异

本项目在设计理念上参考了 Elkeid 的 Agent + Plugin + Server 架构，但在实现上有以下差异：

| 维度 | Elkeid | MxCwpp |
|------|--------|-------|
| 存储 | MongoDB | MySQL + ClickHouse |
| 服务发现 | 独立 SD 服务 | Manager 内嵌 SD 模块（Registry 结构体） |
| SD 同步 | - | Redis Pub/Sub 实时 + 30s 全量兜底 |
| Kafka Topic | 单 Topic | 按数据特征分组 8 Topic |
| 任务分发 | Redis PubSub | 持久化 + 心跳补发 |
| 负载均衡 | 最小连接数 | power-of-two-choices |
| Agent->AC 映射 | Manager 定时采集 | Consumer 消费心跳时写入 |
| 消费失败处理 | - | DLQ（保留原始消息 + 错误 + 重试次数） |

## 关键代码路径

```
cmd/server/manager/              # Manager 入口
cmd/server/agentcenter/          # AgentCenter 入口
cmd/server/consumer/             # Consumer 入口（仅持久化）
cmd/server/engine/               # Engine 入口（检测分析）
cmd/server/llmproxy/             # LLMProxy 入口（LLM 适配网关）
cmd/server/vulnsync/             # VulnSync 入口（漏洞情报融合）
internal/server/manager/sd/      # AC 服务发现与注册（Registry 结构体）
internal/server/common/kafka/    # Kafka Producer / Topic 路由
internal/server/consumer/        # Consumer 路由 / Writer / DLQ
internal/server/consumer/gcppubsub/     # GCP Pub/Sub 消费（GKE 审计日志）
internal/server/engine/          # Engine 16 stages + 子检测包
internal/server/engine/celengine/       # CEL 规则引擎 + 端口扫描检测
internal/server/engine/intrusion/       # 入侵检测 4 大类
internal/server/engine/microseg/        # 微隔离 + K8s NetworkPolicy 推荐
internal/server/engine/storyline/       # ATT&CK 攻击链时间线
internal/server/engine/ml/              # ONNX ML 推理
internal/server/engine/scheduler/       # IOC/规则/漏洞情报同步调度
internal/server/llmproxy/        # LLMProxy: provider / router / cache / quota / audit
internal/server/vulnsync/        # VulnSync: sources / leader / publisher
internal/server/hunting/         # SPL 风格 DSL → ClickHouse SQL 转译
internal/server/database/        # MySQL / Redis / ClickHouse 客户端
internal/agent/                  # Agent 连接 / 传输 / 插件管理
internal/agent/updater/          # Agent 自更新与远程升级
internal/agent/edr/              # Agent 内置 EDR 子模块（25+ 子包）
internal/server/agentcenter/scheduler/  # AC 调度器（任务/心跳/告警/更新等 6 个）
internal/server/manager/biz/     # Manager 业务逻辑（漏洞同步/LLM 接入/SBOM 等）
internal/deploy/cluster/         # 集群部署引擎（mxctl 底层）
internal/common/signing/         # Ed25519 签名/验证
plugins/                         # 11 个插件实现（含 lib/go/ 共享库）
cmd/tools/mxctl/                 # 集群部署 CLI 工具
```
