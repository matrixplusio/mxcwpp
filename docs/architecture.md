# 架构设计

## 概述

MxSec Platform 采用 **Agent + Plugin + Manager / AgentCenter / Consumer** 分层架构。控制面无状态，支持多实例水平扩展；数据面通过 Kafka 异步解耦，按存储特征分层写入 MySQL（业务主数据）和 ClickHouse（时序与事件归档）。

## 系统拓扑

```
                         +--------------------------+
                         |      用户 / 浏览器        |
                         +------------+-------------+
                                      | HTTPS
                                      v
                         +--------------------------+
                         |         Nginx            |
                         |    反向代理 / 负载均衡     |
                         +------------+-------------+
                       /api/*         |         静态资源
                +---------------------+--------------------+
                v                                          v
      +--------------------+                    +--------------------+
      |     Manager x N    |                    |      Vue3 SPA      |
      | REST API / 调度 /   |                    |    前端控制台       |
      | 服务发现 / SD 模块  |                    +--------------------+
      +-------+-----+------+
              |     |
      Prometheus    | MySQL / Redis / ClickHouse
              |     |
              v     v
      +--------------------+                    +--------------------+
      |     Prometheus     |                    |   MySQL / Redis /   |
      |   主机指标数据源    |                    |    ClickHouse      |
      +---------+----------+                    +---------+----------+
                | scrape /metrics                          |
                |                                          |
      +---------+----------+                               |
      |   AgentCenter x N  |------ Kafka Produce -------->|
      | gRPC 接入 / 转发    |                               |
      | Prometheus Exporter |            Kafka --> Consumer x N
      +---------+----------+
                | gRPC BiDi Stream / mTLS
                v
      +------------------------------------------------------+
      |               mxsec-agent（每台目标主机）              |
      |  插件基座 + 生命周期管理 + 服务发现                    |
      |  baseline / collector / fim / scanner / sensor       |
      +------------------------------------------------------+
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

Kafka 异步消费服务，负责数据持久化。

- 订阅 8 个业务 Topic，按 DataType 路由写入 MySQL / ClickHouse
- 幂等写入：MySQL `ON DUPLICATE KEY UPDATE`（逐条 Upsert），ClickHouse `ReplacingMergeTree`
- 批量优化：ClickHouse 5000 条/10s
- 写入失败进 Dead Letter Queue（`{sourceTopic}.dlq` Topic）
- DLQ 消息保留原始消息体、错误信息、重试次数、失败时间
- 不论成功失败均标记 offset，失败消息走 DLQ 而非重试阻塞
- Kafka ConsumerGroup 配置：RoundRobin rebalance 策略，OffsetNewest
- 消费心跳时维护 Redis `agent:ac:{agentID}` 映射，检查 pending 任务触发补发
- CEL 规则引擎集成：eBPF 事件实时匹配告警规则，触发自动响应
- 端口扫描检测器：基于 Redis 滑动窗口的端口扫描行为检测（`consumer/celengine/scan_detector.go`）
- GCP Pub/Sub 消费（`internal/server/consumer/gcppubsub/`）：从 Cloud Logging 接收 GKE 审计日志

入口：`cmd/server/consumer/main.go`

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
| sensor | Tetragon/eBPF 运行时事件采集 | 常驻运行 |
| remediation | 漏洞修复执行（支持 dry-run） | 任务下发 |

插件共享库 `plugins/lib/go/` 提供插件与 Agent 通信的标准接口。

## 数据链路

### 上报链路（Agent -> 存储）

```
Plugin --> Agent Ring Buffer --> gRPC(mTLS) --> AgentCenter
    --> Kafka(按 DataType 路由到 Topic)
    --> Consumer
    --> MySQL / ClickHouse / Redis
```

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
| `mxsec.agent.heartbeat` | 1000, 1001 | 6 | 24h | 心跳/插件状态 -> MySQL |
| `mxsec.agent.events` | 6001, 6002 | 12 | 72h | FIM 文件完整性事件 -> ClickHouse |
| `mxsec.agent.baseline` | 8000-8004 | 6 | 7d | 基线结果/任务完成 -> MySQL |
| `mxsec.agent.asset` | 5050-5060 | 6 | 7d | 资产数据 -> MySQL |
| `mxsec.agent.scanner` | 7000-7004 | 6 | 7d | 病毒扫描结果 -> MySQL |
| `mxsec.agent.ebpf` | 3000-3002 | 12 | 3d | eBPF 运行时事件 -> ClickHouse |
| `mxsec.agent.remediation` | 9100-9299 | 6 | 7d | 漏洞修复任务结果 -> MySQL |
| `mxsec.agent.command-ack` | 9999 | 6 | 7d | Agent 命令执行结果 |

> **DataType 分配详情**: 完整的 DataType 分配表、路由映射和新增检查清单见 [docs/datatype-allocation.md](datatype-allocation.md)。
> **注意**: 6004 (FIM 基线快照) 在 AC 侧直接处理，不走 Kafka；9000/9001 为插件 SDK 内部心跳，禁止业务使用。

Partition Key 为 AgentID，保证同一 Agent 数据有序。Replication Factor = 2，`min.insync.replicas = 1`。

各 Topic 配套 DLQ：`mxsec.agent.{topic-name}.dlq`。DLQ 消息结构包含原始消息体、错误描述、已重试次数和失败时间戳，便于事后排查和重放。

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
| `mxsec:cache:dashboard:stats` | 30s | Dashboard 统计数据缓存，配合 singleflight 防惊群 |
| `mxsec:cache:monitor:host:{range}` | 60s-10m | 主机监控指标缓存，按时间范围不同设置不同 TTL |
| `mxsec:seq:{ruleID}:{hostID}` | rule.Window | 序列检测中间状态，TTL 跟随规则的时间窗口 |
| `mxsec:task:dispatch:lock` | 8s | 任务调度分布式锁 |
| `mxsec:virusdb:update:lock` | 10m | 病毒库更新分布式锁 |
| `mxsec:ioc:{type}` (Set) | 24h | 威胁情报 IOC 集合 |
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
| Consumer | xN 副本 + Kafka ConsumerGroup | Partition 自动 Rebalance（RoundRobin 策略） |
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
| 任务调度 | 5s | 8s | `mxsec:task:dispatch:lock` |
| 病毒库更新 | 4h | 10m | `mxsec:virusdb:update:lock` |

Redis 不可用时降级为无锁模式，依赖调度间隔的自然错开来降低冲突概率。

### 防惊群机制

使用 `singleflight.Group` 确保缓存过期时只有一个 goroutine 发起后端计算，其余 goroutine 共享同一结果。应用场景包括：

- Dashboard 统计数据计算（`mxsec:cache:dashboard:stats`，TTL 30s）
- 主机监控指标聚合（`mxsec:cache:monitor:host:{range}`，TTL 60s-10m）

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

| 维度 | Elkeid | MxSec |
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
cmd/server/consumer/             # Consumer 入口
internal/server/manager/sd/      # AC 服务发现与注册（Registry 结构体）
internal/server/common/kafka/    # Kafka Producer / Topic 路由
internal/server/consumer/        # Consumer 路由 / Writer / DLQ / CEL 引擎
internal/server/database/        # MySQL / Redis / ClickHouse 客户端
internal/agent/                  # Agent 连接 / 传输 / 插件管理
internal/agent/updater/          # Agent 自更新与远程升级
internal/server/agentcenter/scheduler/  # AC 调度器（任务/心跳/告警/更新等 6 个）
internal/server/consumer/gcppubsub/     # GCP Pub/Sub 消费（GKE 审计日志）
internal/server/consumer/celengine/     # CEL 规则引擎 + 端口扫描检测
internal/server/manager/biz/     # Manager 业务逻辑（漏洞同步/LLM/SBOM 等）
internal/deploy/cluster/         # 集群部署引擎（mxctl 底层）
internal/common/signing/         # Ed25519 签名/验证
plugins/                         # 各插件实现（含 lib/go/ 共享库）
cmd/tools/mxctl/                 # 集群部署 CLI 工具
```
