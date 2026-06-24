# 性能 SLO + 大规模架构升级 (P0-9)

## 性能 SLO 矩阵

| 主机规模 | 列表 / Dashboard RT | 全量基线扫并发 | Engine 总吞吐 EPS | Kafka 集群 |
|---|---|---|---|---|
| ≤ 500 | < 200ms | 1k 任务并发 | 5k | 单节点单 broker (3 partitions) |
| 1k | < 3s | 2k 任务并发 | 10k | 1 broker (10 partitions) |
| 3k | < 5s | 6k 任务并发 | 30k | 3 broker (30 partitions) |
| 1w | < 10s | 20k 任务并发 | 100k | 5 broker (100 partitions) |
| 3w+ | < 10s | 60k+ 并发 | 300k+ | 多集群联邦 (C3 已落) |

## 当前架构 ≤ 1k 主机 (开箱即用)

```
   ┌─────────────────────────────────────────────────────┐
   │ Single-Region Deployment                            │
   │                                                     │
   │  Manager (2 replica) ─── MySQL (主从)              │
   │       │                       │                     │
   │       └── AgentCenter (3) ─── Kafka (1 broker)     │
   │              │                  │                   │
   │              ↓                  ↓                   │
   │           Agent (≤1k) ─── Engine (2) ─── CH (单)  │
   │                                                     │
   └─────────────────────────────────────────────────────┘
```

P0-1..P0-8 优化后, 单 Engine 实例支撑 30k EPS, 1k 主机正常吞吐 ~3k EPS, 余量 10x.

## 3k 主机架构升级 (Sprint 8)

### 关键升级点

1. **AgentCenter 水平拆分按 host_id 一致性 hash**
   - 5 AC 实例, Manager SD 按 hostID hash 路由 Agent
   - 单 AC 处理 600 host, gRPC 长连接 ~10k 并发
   - 服务发现 Manager 维护 AC 实例表 + 健康探测

2. **Kafka 集群化 3 broker / 30 partition**
   - 按 tenant_id + host_id 一致性分区
   - 副本 RF=3, ISR=2 保证高可用
   - Engine ConsumerGroup `mxcwpp-engine` 分配 30 partition 给 6 Engine 副本

3. **MySQL 读写分离 + 主从延迟监控**
   - Manager 读 hosts/alerts 走从库 (2 个读副本)
   - 写 (Agent 配置变更 / Alert ack) 走主库
   - GORM Hook 按 SELECT/INSERT 自动路由

4. **ClickHouse 分布式表**
   - `agent_events_distributed` → 3 shard × 1 replica
   - 按 tenant_id hash 分片, Engine 写入自动分发
   - 列表查询走 distributed 表 (跨 shard 并行)

5. **Redis Cluster 6 节点**
   - mode resolver / rollout 桶 / rate-limit / leader election 都走 Redis
   - 主从 + 哨兵, 自动 failover

6. **Engine 水平扩展按 Topic 分片**
   - Engine 6 实例, Kafka ConsumerGroup 自动均衡
   - Stage 内 worker pool 复用 (替每事件 spawn 4 goroutine)

### 配置示例

```yaml
# values-3k.yaml
manager:
  replicaCount: 4
  resources: { requests: {cpu: 1000m, memory: 1Gi} }

agentcenter:
  replicaCount: 5
  agentService: { type: LoadBalancer }   # 5 AC 共享 LB

engine:
  replicaCount: 6
  resources: { requests: {cpu: 2000m, memory: 4Gi} }

externalServices:
  kafka:
    brokers: "kafka-0:9092,kafka-1:9092,kafka-2:9092"
    replicationFactor: 3
    partitions: 30
  mysql:
    primary: "mysql-primary:3306"
    replicas: ["mysql-replica-0:3306", "mysql-replica-1:3306"]
  clickhouse:
    shards: 3
    distributed: true
  redis:
    mode: cluster
    nodes: 6
```

## 1w 主机架构 (Sprint 9-10)

### 单 region 极限 ~3w 主机, 超过需多 region 联邦.

### 关键升级点

1. **AgentCenter 双层路由**
   - L1: Manager SD 按 hostID hash → 10 AC pod
   - 单 AC 长连接 1k host, gRPC HTTP/2 stream 复用
   - 心跳间隔从默认 60s → 自适应 (online 主机分批 90s, offline 主机退避到 5min)

2. **Engine 流水线化分层 Topic**
   - `mxcwpp.agent.events.l1` → 简单 stage (anomaly/intrusion 短路) 8 Engine
   - `mxcwpp.agent.events.l2` → 复杂 stage (storyline/CEL) 16 Engine
   - 两级处理避免单 Topic 串行限制

3. **Kafka 集群 5 broker / 100 partition**
   - 单 partition 吞吐 10k EPS, 100 partition 全集群 1M EPS 理论上限
   - 实际 100k EPS 工作负载, 10% 利用率有充足头寸

4. **MySQL 分库 (按 tenant_id 取模)**
   - 8 数据库实例, 单实例 ~1.5k 主机
   - 大租户 (>2k host) 独占 1 实例
   - GORM Sharding plugin 自动路由

5. **ClickHouse 7 shard × 3 replica**
   - 21 节点, 21 TB 存储 (按 90 天 retention)
   - 跨 shard 查询走 distributed engine

6. **Object Storage (S3 / OSS) 接 ClickHouse**
   - 90 天前数据自动归档到 S3 (Tiered Storage)
   - 节省 60% CH 本地 SSD 成本

7. **Manager API Edge cache (Nginx + Redis)**
   - hosts/alerts list 30s TTL cache (按 tenant_id + 查询参数 hash)
   - 命中率 80%+ → DB 压力降 5x

### 配置示例 (values-10k.yaml)

```yaml
manager:
  replicaCount: 8
  ingress: { className: nginx, annotations: {nginx.ingress.kubernetes.io/server-snippet: "proxy_cache_path ..."} }

agentcenter:
  replicaCount: 10
  agentService: { type: LoadBalancer, externalTrafficPolicy: Local }

engine:
  # 两层 Engine
  replicaCount: 24   # 8 l1 + 16 l2

kafka:
  brokers: 5
  partitions:
    "mxcwpp.agent.events.l1": 50
    "mxcwpp.agent.events.l2": 100
    "mxcwpp.engine.alert": 50
```

## 3w+ 多 region 联邦 (Sprint 11+)

走 C3 (PR194) 联邦架构: 中心 Manager 聚合多个 region 子集群心跳, 每 region 独立单 region 部署 (≤1w 主机). 3 region × 1w = 3w. 5 region × 1w = 5w.

### 数据流

```
   ┌────────────────────────────────────────────┐
   │ 全局 Manager Console                       │
   │   ↑ Heartbeat (60s, 摘要 KB 级)            │
   │   │ PullAlert (on-demand 用户查具体告警)   │
   ├───┴────────────────────────────────────────┤
   │ Region A Manager ←→ Region B ←→ Region C  │
   │  (1w 主机)         (1w)        (1w)        │
   └────────────────────────────────────────────┘
```

每 region 数据本地化, 满足 GDPR / 等保 数据驻留. 跨 region 仅传摘要 + 用户主动 query.

## 性能优化已完成 (P0 全部)

| ID | 项 | 效果 |
|---|---|---|
| P0-1 | Kafka Sync → Async + batch | 50k EPS (10x) |
| P0-2 | NPatch BPF fastpath + 256 | cgroup_skb 3-5x |
| P0-3 | RASP UDS batch flush | syscall ↓ 90% |
| P0-4 | CEL DataType 分桶 | 检测延迟 10x |
| P0-5 | Pipeline 解码一次共享 | CPU ↓ 60% |
| P0-6 | YARA 预编译 + cache | 扫描 10x |
| P0-7 | UI bundle 拆 + keep-alive | 首屏 70% |
| P0-8 | updater ed25519 签名 | 安全 (商业级必须) |

## 下一阶段优化 (P1 持续)

- 异步通知 goroutine pool 限并发 (consumer/writer/mysql.go)
- baseline 引擎 errgroup 并行 + fork 限流
- vulnsync http.Transport 共享池
- TLS cert cache + fsnotify watch
- ML stage DataType 过滤
- Storyline LRU + pendingEvts 上限
- transport 退避 jitter
- gRPC MaxConnectionAge
- json.Unmarshal sync.Pool
- DB 联合 index (tenant_id, status, severity)
- hosts.go 大事务拆批

实施时间: Sprint 8 一个 sprint 周期可达 1k 主机 SLO, Sprint 9-10 达 1w SLO.
