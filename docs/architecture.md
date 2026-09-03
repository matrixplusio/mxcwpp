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
- LLM 告警辅助分析（`internal/server/llmproxy/llm_assist.go`）
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
- HTTP 管理接口：`/health`（匿名 liveness）+ `/conn/stat` `/conn/list` `/command` `/command/batch` `/dependency/install`（强制 `X-Internal-Secret` 内部鉴权，详见「安全与通信」）
- 启动时向 Manager SD 注册（重试 3 次），15s 心跳（包含 ConnCount），优雅注销
- 主机性能指标通过 `/metrics` 暴露给 Prometheus 抓取
- 内置 8 个调度器（`internal/server/agentcenter/scheduler/`）：插件更新、Agent 更新、Agent 重启、
  任务超时、心跳超时检测、插件推送超时、**IOC 同步**、**规则同步**
- 后台调度器启动自检：每个调度器在 `Start` 中调用 `MarkStarted`，启动后比对
  `ExpectedSchedulers`，缺失即 ERROR 日志 + `mxcwpp_ac_scheduler_missing` 指标置 1。
  这不是冗余——AC 曾有两份初始化文件并存，IOC 同步与规则同步的装配只写在
  没有调用方的那份里，两项能力因此静默缺失数月：编译通过、启动正常、日志干净，
  而全机群 `edr_ioc_count` 为 0、agent 规则无法热更新。
  静态清单挡不住这类问题（代码里确实"有"那一行，只是在死文件里），
  只有运行时事实能挡住

入口：`cmd/server/agentcenter/main.go`

### Consumer

Kafka 异步消费服务，**仅负责数据持久化**（v2.0 起检测能力已剥离至 Engine 服务）。

- 订阅 8 个业务 Topic（ConsumerGroup A "mxcwpp-consumer"），按 DataType 路由写入 MySQL / ClickHouse
- 幂等写入：MySQL `ON DUPLICATE KEY UPDATE`（逐条 Upsert），ClickHouse `ReplacingMergeTree`
- 批量优化：ClickHouse 5000 条/10s
- 写入失败进 Dead Letter Queue（`{sourceTopic}.dlq` Topic）
- DLQ 消息保留原始消息体、错误信息、重试次数、失败时间
- 消费失败走 DLQ 而非重试阻塞；但 **ClickHouse 刷盘失败时提交屏障不推进 offset**，
  消息会被重新投递（宁可归档里多出重复行，也不能提交"已落盘"却其实没落盘）
- Kafka ConsumerGroup 配置：RoundRobin rebalance 策略，OffsetNewest
- 消费心跳时维护 Redis `agent:ac:{agentID}` 映射，检查 pending 任务触发补发
- GCP Pub/Sub 消费（`internal/server/consumer/gcppubsub/`）：从 Cloud Logging 接收 GKE 审计日志

入口：`cmd/server/consumer/main.go`

### Engine

v2.0 新增的检测分析引擎，独立服务，与 Consumer 并行消费 Kafka。

- 订阅 `mxcwpp.agent.*` 全部业务 Topic（ConsumerGroup B "mxcwpp-engine"），与 Consumer 互不影响 offset
- **检测 Stage**（`internal/server/engine/stage_*.go`）：清单以 `capability.go` 为准，
  当前 14 个定义中 **13 个已接入流水线**——CEL / Sequence / IOC / PortScan / Storyline /
  Privilege / RASP / Anti-Rootkit / Rootkit / ReverseShell / PrivEscalation /
  BruteForce / Webshell。
  仅 `abnormal_login` 未接线（画像冷启动会对每台主机的首次登录误报，见路线图）
- 多层检测子包：
  - `celengine/` — CEL 规则引擎，eBPF 事件实时匹配 + 自动响应触发。
    规则按 `draft → shadow → context → alert` 分级，晋级门槛由人工研判结论决定
    （见 [API · 规则生命周期](api-reference.md#规则生命周期)）；
    ML 异常分经 `host_anomaly_scores` 参与告警排序，加权封顶 1.15，跨不过严重度档
  - `intrusion/` — 入侵检测合集（abnormal_login / reverse_shell / rootkit / webshell）
  - `adaudit/` — AD/LDAP 域控审计 7 条规则（DCSync / Kerberoasting / 暴破等）
  - `microseg/` — 微隔离流量识别 + 策略生成 + Kubernetes NetworkPolicy 推荐
  - `kube/` — K8s Audit Event 检测（PSS 等）
  - `rasp/` — RASP 事件汇聚（Java / Python / PHP / Node / Go）
  - `honeypot/` — 反勒索 / 蜜罐告警归并
  - `ml/` — Go 原生 IForest + Registry。**未接线**（capability 清单 `ml_anomaly` = unwired），
    且**没有 ONNX**：go.mod 无 onnxruntime 依赖，ONNX 适配仍是 TODO
  - `anomaly/` — 行为基线异常检测（IForest + 多指标关联）。四档 `off/shadow/context/ranking`，
    **1.0 不开放 alert 档**；含长期参照基线（抗训练投毒）、模型版本与回滚、按主机配额的训练采样。
    详见 [ML 异常检测安全说明](ml-anomaly-safety.md)
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

入口：`cmd/server/vulnsync/main.go`

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

各 Topic 配套 DLQ：`mxcwpp.agent.{topic-name}.dlq`。DLQ 消息结构包含原始消息体、错误描述、已重试次数和失败时间戳。

**重放**：`cmd/tools/dlq-replay` 把 DLQ 消息投回原 Topic 交回正常消费链路。

```bash
dlq-replay -config /etc/mxcwpp/server.yaml -topic mxcwpp.agent.events           # 预演
dlq-replay -config /etc/mxcwpp/server.yaml -topic mxcwpp.agent.events -apply    # 执行
```

刻意做成人工触发而非自动重放：DLQ 里既有下游临时故障导致、重放即可恢复的消息，
也有字段非法这类重放多少次都会再失败的毒消息；自动重放会让后者在队列间无限循环。
默认预演不投递也不推进位点，`-max-retry`（默认 3）之上的消息视为毒消息跳过，
投递用同步生产者确认成功后才推进位点，中途失败可直接重跑。

## 存储分层

| 存储 | 定位 | 写入方 |
|------|------|--------|
| MySQL 8.0+ | 业务主数据（主机、策略、任务、告警状态、资产快照、用户） | Consumer / Manager |
| ClickHouse | 时序分析与事件归档（指标趋势、FIM、告警时间线、审计日志） | Consumer |
| Redis | SD 同步、`agent:ac` 映射、分布式锁、基线评分缓存、防惊群 | Manager / Consumer |
| Prometheus | 主机性能指标查询源（CPU / 内存 / 磁盘 / 网络） | AgentCenter Exporter |

### 数据保留：两套机制，各管一边

`retention_policies` 表定义各类数据的保留天数，但它**只会被下发成 ClickHouse 的
TABLE TTL**（`admin_data_config` 改保留期时执行 `ALTER TABLE ... MODIFY TTL`）。

而 `feature_flag.data_source.*` 决定同一类数据实际写哪边，默认值全部是 `mysql`。
两者叠加的后果是：数据写在 MySQL，保留期只对 ClickHouse 生效。2026-08
`storyline_events` 因此涨到 亿级行、数百 GB 写满存储节点，级联拖垮整个平台。

现在 MySQL 侧由 `manager/scheduler/mysql_retention.go` 独立清理，每 6 小时一轮、
分批删除避免长事务锁表。两条约束：

- **白名单而非全表遍历**。这些表语义不一致：`kernel_modules` 有 225/228 台主机
  只存在单个 `collected_at`，它是覆盖式的当前快照而非历史流水，按时间删等于
  抹掉资产数据。快照类表要的是"每主机保留最近 N 份"，不在本机制范围内。
- **只清理仍在上报的主机**（`ScopedToLiveHosts`）。主机停报后它的历史行会随时间
  全部越过保留期，最后已知状态就凭空消失了——而这类主机恰恰是排查时最需要
  数据的那些。停报主机的数据原样保留，直到主机本身下架。

改数据源（`data_source.*` 由 `mysql` 改 `ch`）需重启对应进程：写入目标在启动时
读一次 flag，运行期不动态变更。

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
| Manager <-> AgentCenter | HTTP 内部接口 | `X-Internal-Secret` 共享密钥（常量时间比较） |

**mTLS 细节**：AgentCenter 的 TLS 配置使用 `VerifyClientCertIfGiven` 策略——单一监听端口无法对 enroll 与正常流分别设置 `ClientAuth`，故用「TLS 放行 + 应用层强制」的组合：无客户端证书的连接只能走 Transfer 的 enroll 阶段，其余所有 RPC 由拦截器要求已验证的客户端证书。

**gRPC Keepalive**：Time=60s（空闲后发 ping），Timeout=10s（ping 等待响应超时），MinTime=10s（客户端最短 ping 间隔）。

证书生成：`scripts/generate-certs.sh`

### AgentCenter 管理端口鉴权与网络边界（E-SEC-1）

AC HTTP 管理端口承载高危接口，威胁模型与访问控制：

| 接口 | 鉴权 | 说明 |
|------|------|------|
| `/command` `/command/batch` `/dependency/install` | 强制 `X-Internal-Secret` | 可向 Agent 下发任务，无凭据返回 401，handler 不执行 |
| `/conn/stat` `/conn/list` | 强制 `X-Internal-Secret` | 泄漏在线 Agent 清单，同上保护 |
| `/health` | 匿名 | 仅最小 liveness（`{"status":"ok"}`），不含在线明细；供 Manager SD 探活 |
| `/metrics` | 匿名 | Prometheus 抓取；由部署拓扑保证仅受控网络可达，不发布到宿主公网 |

- 共享逻辑在中立包 `internal/server/common/internalauth`（Manager 与 AC 共用；对提供值与密钥各做 SHA-256 归一为定长摘要后再 `subtle.ConstantTimeCompare`，避免长度侧信道；空密钥 fail-closed 一律拒绝；不记录密钥）。
- Manager 侧命令分发 / 依赖安装（`sd.ACDispatcher`）精准路由与广播均携带同一密钥。
- Manager 的内部服务路由 `/api/v1/internal/ac/*`、`/api/v1/internal/alerts/*` **始终挂载** `internalauth.Middleware`——空密钥时由中间件 fail-closed 返回 401，绝不匿名可达。
- **启动 fail-fast（不留静默半失效）**：
  - AgentCenter：`Config.ValidateAgentCenter()` 经 `ValidateInternalSecret` **无论绑定地址如何**都强制非空、非模板占位符、非弱默认值、长度 ≥32 的 `server.internal_secret`——空密钥下 AC 受保护接口全部 401、注册/命令下发永久失败，故 loopback 也拒绝空密钥启动；非 loopback 额外强调管理面裸奔风险。
  - Manager：`Config.ValidateManager()` 在打开内部路由前强校验同一密钥，失败即退出（仅 Manager 专用初始化路径调用，不影响 Consumer/Engine 等共用 Config 的进程）。
  - 集群部署（`internal/deploy/cluster`）在 `Config.Validate()` 强校验 `app.internal_secret`，Manager 与所有 AC 渲染同一密钥。
- **Manager 与 AC 必须配置同一 `server.internal_secret`**（含本地开发；否则 AC↔Manager 注册与命令下发被 401 阻断）。
- 密钥来源：`server.internal_secret`（deploy.sh 从 `.env` 的 `INTERNAL_SECRET` 生成/幂等持久化为唯一强行；集群从 `app.internal_secret` 渲染）。

### 单租户收敛（E-TEN-1）

产品定位是**单租户** Linux/K8s CWPP。曾存在的多租户/托管产品面已移除：

| 已删除 | 说明 |
|---|---|
| `biz/billing`、`biz/federation` | 删除时均为零外部引用的死代码 |
| `biz/mssp` + `/api/v2/mssp/*` | MSSP 跨租户控制台，属托管服务产品线 |
| `/api/v2/admin/tenants/*` | 租户 CRUD、停用/恢复、按租户切换运行模式 |

共移除 14 条路由。运行模式查询 `/api/v2/system/mode` 保留，但**不再按租户切换**——
模式是部署级设置。

**底层 `tenant_id` 刻意保留**：262 处过滤点统一传默认租户 `t-default`。删列是高风险
数据迁移，收益只是少一个字段；收敛的是产品面，不是数据模型。将来若真要多租户，
数据侧不必从头再来。

`internal/server/manager/router/single_tenant_test.go` 守住这条边界：多租户路由或已删包重新出现即失败。

### 事件运营闭环（E-OPS-1）

事件此前只有 `active/investigating/resolved` 三态和一个 `resolved_by`（实际只会写
`auto`）：**没有负责人、没有响应时限、没有研判结论、关闭不需要理由**。
检测做得再准，产出的也只是越积越多、最后没人看的告警——发现问题的能力没有变成处理问题的能力。

闭环长在既有 `Incident` 上，而不是另建平行的 Case 表：关联逻辑、风险聚合、成员告警
都已在那里，两张表只会产生两份互相不同步的事实。

| 环节 | 语义 |
|---|---|
| 指派 / 认领 | 分开记录。**被指派不等于有人开始看**，混为一谈会让 MTTA 失真；重复认领不刷新时间，MTTA 记的是第一个真正开始看的人 |
| SLA | 事件创建时按严重级别算出认领与解决时限。一刀切要么低危把人拖垮、要么高危被淹没；未知级别退到最宽，不因拼写错误把人叫醒 |
| 研判 | 关闭**必须**给出 `true_positive` / `false_positive` / `benign_true_positive` |
| 升级 | 必须写明对象与原因，否则"已升级"事后无从追溯 |
| 关闭 | **必须写明原因**，且记录真实操作人 |

`incident_events` 单表承载状态变更、研判备注与证据引用。不拆成评论/审计/证据三张：
调查过程本身是一条连续叙事，拆开后"谁在什么时候基于什么做了什么决定"需要跨表拼接，
而这恰恰是复盘唯一要看的东西。状态变更与时间线记录同事务写入——状态变了却没有记录，
等于事后无法解释这个决定是谁做的。

**`benign_true_positive` 单列一档**很关键：检测正确但行为无害（如运维自己的操作），
把它算进误报会让规则被错误地调松。

研判结论同时是检测质量的唯一可信来源——precision 只能由它算出。拿 `resolved` 数量代替，
会把"没人看所以批量关掉"算成检测准确。

### 人工响应与硬禁自动处置（E-OPS-3）

隔离主机会切断业务流量。原实现是**一次 API 调用即刻生效**：没有第二个人看过、
没有幂等键、没有回滚记录，事后也回答不了"这台机器当时为什么被隔离、谁批的"。

处置现在走完整生命周期：`pending → approved/rejected → executed/failed → rolled_back`。

| 约束 | 理由 |
|---|---|
| **未审批不得执行** | 判断做成 `ResponseAction.Executable()` 而非散在调用方，新增执行入口不会"忘了检查审批" |
| **申请人不得自审批** | 同一个人既提又批，审批就只是多点一次鼠标 |
| **幂等键唯一索引** | 处置重复执行的后果不对称——多隔离一次可能切断本已恢复的业务。靠数据库挡并发重复，而不只是提交前查一次 |
| **失败与未执行区分** | 前者要人去查为什么没生效，后者只是还没轮到 |
| **驳回必须写原因** | 否则申请人不知道该改什么 |

**硬禁自动处置的落点**是申请入口：`system` / `auto` / `scheduler` / 空身份一律拒绝。
只靠"目前没有自动路径"是碰巧成立而非设计保证——`ShouldEnforce` 仅在 pipeline 填字段
和未接线的 admission 出现，将来任何自动化想调用处置，都会在这道闸门上失败，
而不是悄悄执行成功。

处置全过程回流为事件时间线上的证据，带幂等键便于追溯：复盘要能顺着一条时间线
看完"发现→研判→申请→审批→执行"，而不是去另一个页面拼。

### 值班表与响应时限（E-OPS-2）

事件闭环加了认领与解决时限，但**没有任何东西去读它们**——没人看的截止时间只是一列
数据，与「埋了点没人告警」是同一种毛病。现在两侧都补齐：

**值班表** `oncall_shifts` 按时间窗排班，分 `l1 / l2 / security` 三层。
新事件创建时自动派给当班的一线值班人——不自动派单的话，事件默认无人负责，
超时告警只会天天响而没人知道该找谁。

排班按时间窗而非固定人：值班是轮换的，把负责人写死在配置里意味着换班要改配置。
同一时段多人时取最早开始的那位——"大家都在班"等于"没人负责"。

**无人值班不静默跳过**：留下一条时间线记录。排班缺口本身就是运维要处理的问题，
藏起来只会让事件一直无主。派单失败也不影响事件落库——把创建和派单绑成一体，
会让排班缺口变成"事件也没了"。

**升级沿层级向上**，目标由值班表算出而非手工填写：让人在半夜三点自己想"升级给谁"
是行不通的。已在最高层时明确报错，不假装升级成功。

**超时检测**每 2 分钟一轮，只观测不改状态——自动把超时事件标记成别的状态会掩盖问题，
超时该做的是让人知道，而不是让它从待办里消失。指标用 Gauge 而非 Counter：
运维要问的是"现在有多少条没人管"，不是"历史上超时过几次"。

| 指标 | 含义 |
|---|---|
| `mxcwpp_incident_sla_breached{kind,severity}` | 当前超过认领/解决时限的事件数 |
| `mxcwpp_incident_unowned` | 无负责人的未关闭事件数（即将变成超时的前兆） |

一条无人认领的高危事件，与一条未被检出的攻击，对客户来说结果是一样的。

### 单一外发出口（E-DEL-4）

`biz/outbound` 下有 9 个连接器（Splunk HEC、QRadar LEEF、Elastic、阿里云 SLS 等），
**全部零外部引用**；`SetSIEMForwarder` 只有定义、零调用。Consumer 里确实构造了
Forwarder 并打印"SIEM 转发器已启动"，然后**从未调用过它**——日志说它在跑，
实际一条告警都发不出去。「可对接你现有 SIEM」此前是不成立的。

现在只留一个出口：**CEF over Syslog**（`siem` 配置段，默认关闭）。9 个死连接器已删。

**外发与通知是两件事**，这决定了它在流水线中的位置：

| | 通知 | 外发 |
|---|---|---|
| 目的 | 叫醒人 | 把记录交给客户日志系统 |
| 类别灰度 | 受限 | **不受限** |
| 等级门槛 | 受限 | **不受限** |
| 抑制窗口 | 受限 | **不受限** |

抑制是为了少打扰人，不是为了让客户 SIEM 少收记录。若外发也走抑制，客户侧会出现
平台单方面造成的缺口，而他们无从知道少了什么。因此外发发生在所有通知门槛**之前**。

**覆盖全部告警源**。alerts 表那条链路（CEL/Sequence/IOC + Stage 告警）自带通知，
接入时标记 `EgressOnly`：只外发、不重复通知。只导一部分比不导更危险——客户会以为
自己收全了。

**有界异步**。底层 `SendAlert` 持锁写 socket、超时 5 秒；原 CEL 路径是每条告警起一个
goroutine 去抢同一把锁，告警风暴下会堆出大量阻塞协程。现在统一走有界队列，
满则丢弃并计入 `mxcwpp_alert_egress_total{outcome="dropped_queue_full"}`——
宁可外发缺条目也不拖慢检测，但丢弃必须可见。

### 恶意文件扫描的结果复态（E-DEL-4）

ClamAV / YARA 引擎不可用（未安装、内存不足）或执行出错时，扫描器此前返回
`(nil, nil)`——调用方读到"零威胁、无错误"，任务上报 `status=completed`、
`threat_count=0`。**一台根本没装 ClamAV 的主机，平台报告它没有恶意文件。**

现在每个引擎给出执行回执（`scanned` / `unavailable` / `failed`），由回执推导整体结论：

| 结论 | 含义 |
|---|---|
| `clean` | 所有引擎都跑了，未发现威胁 |
| `infected` | 发现威胁（即便另一引擎未跑成，已确认的威胁不降级） |
| `partial` | 部分引擎未跑或出错，覆盖不全，**不足以判定主机干净** |
| `unavailable` | 无任何引擎可用，本次根本没有扫描发生 |

任务完成信号带上 `scan_status` 与逐引擎回执；服务端把覆盖不全的主机计入
`antivirus_scan_tasks.degraded_hosts`，非零即代表"任务显示扫完了，但这些主机没被扫过"。

**没扫是覆盖缺口，不是结论**——这与"请求失败渲染成 0"是同一类问题：
把"不知道"显示成"没问题"。

### 可观测性与告警覆盖（E-OBS-1）

平台此前的典型形态是"埋了点、没人报警"：agent 丢事件、engine 背压丢弃、Stage 报错
三个指标一直在采集，图表上看得见，却没有任何规则会把人叫醒。数据在丢而无人知晓，
与没有这些指标没有区别。

关键指标必须有对应告警，由 `internal/deploy/alertcoverage_test.go` 把清单钉住——
新增关键指标未补规则即失败：

| 指标 | 含义 |
|---|---|
| `mxcwpp_agent_event_dropped_total` | Agent 丢事件 = 该主机检测盲区 |
| `mxcwpp_engine_backpressure_drop_total` | Engine 背压丢弃 = 漏检 |
| `mxcwpp_engine_stage_errors_total` | Stage 持续报错 = 该项能力静默失效 |
| `mxcwpp_consumer_dlq_write_failures_total` | DLQ 写失败 = 消息不可恢复地丢失 |
| `mxcwpp_consumer_ch_write_errors_total` | CH 写失败 = offset 暂停推进 |
| `mxcwpp_ac_unrouted_datatype_total` | DataType 未登记路由 = 消息被静默忽略 |
| `mxcwpp_vulnsync_last_success_timestamp_seconds` | 漏洞库停更 = 界面显示的是旧数据 |

漏洞库新鲜度刻意计量"距上次成功多久"而非"跑了多少次"：后者在任务反复失败时同样
在增长，只有前者能回答"我现在看到的漏洞数据可信到什么时候"。同步失败**不更新**
该时间戳，否则停更时告警永远不会触发。

### 运行时能力清单（E-WIRE-1）

代码里有 19 个检测 Stage 构造器，实际接进流水线的只有 8 个；接进去的里面还有 3 个把
告警发往 `mxcwpp.engine.alert`，而该 topic **无任何消费者**——跑了也到不了界面。
"有代码"与"能力在跑"之间隔着两道口子，此前只能靠人工 grep 分辨，数字还互相对不上。

`internal/server/engine/capability.go` 是权威清单，把每项能力归入三档之一：

| 档位 | 含义 | 可否对外宣称 |
|---|---|---|
| `active` | 已接线且告警有实际去处 | ✅ |
| `dead_end` | 已接线但告警无人消费 | ❌ 必须注明缺什么 |

| `unwired` | 有构造器但从未接线 | ❌ |

清单经 `GET /capabilities`（Engine HTTP）以 JSON 发布，供运维与交付流程核对。

门禁 `capability_test.go`（`make test`）双向比对清单与真实代码：新增构造器未登记、声明已接线
但入口没接、声明未接线却接了，三种都会失败。`dead_end` 条目必须写明原因，且一旦
`engine.alert` 出现消费者，测试会提示把状态改回 `active`——避免修好了却忘了更新清单。

**对外宣称以清单为准**：只有 `active` 档的能力允许出现在方案、官网或 POC 中。

### 单一告警落库链路（E-DET-1）

流水线里每个 Stage 的告警都会发往 `mxcwpp.engine.alert`，而该 topic 至今无消费者。
CEL / Sequence / IOC 之所以能出现在界面上，是因为它们额外挂了 `AlertGenerator`
自行落库；Privilege / RASP / AntiRootkit 没挂——检测在跑、告警在发、界面永远看不到。

现由流水线统一落库：不实现 `PersistsOwnAlerts()` 的 Stage，其告警经
`StageAlertWriter` 写入 `alerts` 表，`result_id = engine-{ruleID}-{hostID}`（不含
时间戳，重复命中累加 `hit_count` 而非刷行），已处置告警复发会回到活跃态。

自带落库的 Stage 通过 `PersistsOwnAlerts()` 显式声明，流水线据此跳过，避免同一次
命中被写两遍。不复用 `AlertGenerator` 是因为它与 CEL 深度耦合（数字 `rule.ID`、
`cel-%d` 结果键、依赖规则字段的低保真与观察期判定），给硬编码 Stage 合成假规则
会让它们伪装成 CEL 规则并误用只对 CEL 有意义的治理语义。

### Agent 身份信任链（E-SEC-3）

Agent 接入的信任建立在三段上，任一段缺失都会被 fail-closed 拒绝：

1. **首连锁定 AC 身份**。本地无 CA 文件时，Agent 用构建期嵌入的 CA 指纹做完整 pinned-root 校验：指纹命中的证书必须确为 CA，叶子证书必须由该 CA 验签通过，且 SAN 命中目标主机名、用途含 `serverAuth`。仅「链中出现该 CA」是不够的——攻击者可以把公开的 CA 证书塞进伪造链。缺少合法指纹时**在连接前失败**，不回退无 pin 的 `InsecureSkipVerify`。
2. **enroll 换一机一证**。无客户端证书的 Agent 只能 enroll：提交合法 AgentID 与 enroll 令牌（定长摘要 + 常量时间比较，空令牌一律无效），AC 现签 `CN=AgentID` 的单机证书并下发后即结束该流。enroll 期间不注册连接、不处理心跳、不下发插件任务。
3. **稳态强制身份绑定**。持证连接强制客户端证书 CN == 上报 AgentID，吊销序列号在握手期拒绝；非 Transfer 的 RPC 一律要求已验证客户端证书。

一机一证使失陷主机可单独吊销，且私钥泄露不波及他机。生产构建的安装包不再下发共享 client 证书。

`insecure_dev_mode` 是唯一放宽通路，被限制为仅在 gRPC 与 HTTP 均绑定回环时可用，官方部署渲染永不设置。

### 下发命令的执行边界（E-SEC-4）

平台会把命令下发到 Agent 并以 root 执行，因此「谁能编辑内容」等价于「谁能在全舰队执行代码」。执行侧统一采用**结构化 argv + 显式允许集**，不再使用「危险词黑名单 + shell 字符串」：

| 链路 | 边界 |
|------|------|
| 漏洞修复（`plugins/remediation`） | 命令切成 argv，逐项对照允许的程序 / 子命令 / 选项 / 操作数，**不经 shell** 执行；操作数不得为路径、URL 或包文件 |
| 远程取证（`internal/agent/forensics`） | 只读取证程序白名单，同样 argv 化、不经 shell；排除 `find`（`-exec`/`-delete` 无法约束为只读）、解释器与下载工具 |
| 基线 `command_exec` / `fix.command` | 自定义规则禁止**新增**（创建、更新、策略导入三个写入口一致）；**存量**由派发闸门按配置上报或拦截；内置规则不受限 |

基线规则的信任来源是 `builtin` 标记：它只由服务端的规则文件同步与一次性迁移设置，任何用户请求都改不了它，因此已足以区分「随发布分发的官方规则」与「用户自建规则」，无需再叠一层 manifest 签名。

存量自定义可执行规则的处置分两步：`GET /api/v1/policies/custom-exec-rules` 出清单供人工研判，确认可收紧后再开启 `server.security.block_existing_custom_exec_rules`。默认只记审计不拦截——默认拦截会静默削减既有基线覆盖面。派发闸门是**进程级**策略而非 TaskService 实例字段：该服务有 6 处构造点且多数拿不到 Config，做成实例字段等于埋下「某条派发路径漏设、闸门在那条路径上静默失效」的分叉。

不采用前缀白名单的原因：前缀只约束第一个词，参数空间完全开放，而只要还经 `sh -c`，未被枚举的语法（换行分隔、命令替换、重定向）就都是缺口。共享校验位于 `internal/common/execpolicy`。

`rpm` 与 `dpkg` 的安装操作只接受文件路径，而安装本地包必然以 root 运行包内维护者脚本——不存在安全的操作数形式，故整体移除；装包一律走包管理器按包名从已配置仓库取。

### RBAC deny-by-default 与路由覆盖闸（E-SEC-2）

- 所有 JWT 认证路由（`apiV1Auth`）走 `EnforcePermissions`：按「模块 × 动作」（view/manage/respond）校验；**未登记路由对非 admin 一律拒绝（deny-by-default）并记 `access.denied` 审计**，不再因空映射放行；admin 为显式超管通路。
- `/api/v2` 管理面路由（`/admin`、`/config/change-requests`、`/mssp`）显式 admin 门禁；`/system/mode` 为登录即可的只读查询。
- 路由分类权威表 `internal/server/manager/api/route_policy.go` 把每条注册路由归为 public / internal / authenticated-perm / authenticated-basic / admin 之一（public/basic 用**精确 method+path**，不用前缀吞并）。
- **精确路由 golden manifest** `internal/server/manager/router/testdata/routes.golden` 逐条记录 `METHOD PATH CLASS PERM`。测试 `route_manifest_test.go` 把**实际 `engine.Routes()`** 与 golden 双向比对：新增未登记路由、陈旧条目、class/permission 变化均失败（新增路由不会被宽泛 prefix 自动吞掉）。改动路由后用 `go test ./internal/server/manager/router/ -run TestRouteManifest -update-routes` 重新生成，由人工审查 diff（测试本身不自增改 golden）。
- 运行时门禁验证 `route_gating_test.go`：对 internal / authenticated / admin / public 各类代表路由发真实无凭据请求，断言在 handler 前被相应机制拦截（分类 = 实际门禁）。

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
internal/server/audit/           # 操作审计中央记录器（中立共享：manager + agentcenter 各自 Init）
internal/server/manager/sd/      # AC 服务发现与注册（Registry 结构体）
internal/server/common/kafka/    # Kafka Producer / Topic 路由
internal/server/consumer/        # Consumer 路由 / Writer / DLQ
internal/server/consumer/gcppubsub/     # GCP Pub/Sub 消费（GKE 审计日志）
internal/server/engine/          # Engine 16 stages + 子检测包
internal/server/engine/celengine/       # CEL 规则引擎 + 端口扫描检测
internal/server/engine/intrusion/       # 入侵检测 4 大类
internal/server/engine/microseg/        # 微隔离 + K8s NetworkPolicy 推荐
internal/server/engine/storyline/       # ATT&CK 攻击链时间线
internal/server/engine/ml/              # Go 原生 IForest（未接线，无 ONNX）
internal/server/engine/scheduler/       # IOC/规则/漏洞情报同步调度
internal/server/llmproxy/        # LLMProxy: provider / router / cache / quota / audit
internal/server/vulnsync/        # VulnSync: sources / leader / publisher
internal/server/hunting/         # SPL 风格 DSL → ClickHouse SQL 转译
internal/server/database/        # MySQL / Redis / ClickHouse 客户端
internal/agent/                  # Agent 连接 / 传输 / 插件管理
internal/agent/updater/          # Agent 自更新与远程升级
internal/agent/edr/              # Agent 内置 EDR 子模块（25+ 子包）
internal/server/agentcenter/scheduler/  # AC 调度器 8 个（更新/超时/IOC 同步/规则同步）+ 启动自检
internal/server/manager/biz/     # Manager 业务逻辑（漏洞同步/LLM 接入/SBOM 等）
internal/deploy/cluster/         # 集群部署引擎（mxctl 底层）
internal/common/signing/         # Ed25519 签名/验证
plugins/                         # 11 个插件实现（含 lib/go/ 共享库）
cmd/tools/mxctl/                 # 集群部署 CLI 工具
```
