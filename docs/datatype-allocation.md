# DataType 分配表

**最后更新**: 2026-06-09 | **维护者**: Kerbos

> **强制规则**: 新增任何 DataType 前必须先在本文档注册，确认无冲突后再写代码。
> 违反此规则会导致消息被错误路由（静默丢弃或写入错误 Topic），排查成本极高。

---

## 分配总览

```
0000 ─────────────── (保留)
1000-1099 ─────────── 心跳 / 健康检查
2000-2999 ─────────── (保留，未来扩展)
3000-3099 ─────────── eBPF 运行时事件
4000-4999 ─────────── (保留，未来扩展)
5050-5060 ─────────── 资产采集
5061-5099 ─────────── 资产采集扩展（预留）
6000-6099 ─────────── FIM 文件完整性监控
7000-7099 ─────────── 恶意文件扫描
8000-8099 ─────────── 基线合规检查
9000-9001 ─────────── 插件 SDK 内部心跳（禁止业务使用）
9100-9299 ─────────── 漏洞修复
9300-9399 ─────────── 威胁情报（IOC 分发）
9400-9499 ─────────── 规则分发（Agent 检测规则）
9500-9899 ─────────── (保留，未来安全模块)
9900-9999 ─────────── 控制指令 / 命令回包
```

---

## 详细分配

### 心跳 (1000-1099) → Kafka: `TopicHeartbeat`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 1000 | Agent→Server | Agent 主心跳（在线状态、系统指标） | Agent | Consumer→MySQL + ClickHouse + Redis |
| 1001 | Plugin→Server | 插件心跳（CPU/RSS/FD 进程指标） | Plugin | Consumer→ClickHouse |
| 1002-1099 | - | **未分配** | - | - |

### eBPF 运行时事件 (3000-3099) → Kafka: `TopicEBPF`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 3000 | Agent→Server | 进程事件 (exec/exit) | Agent 内置 EDR 引擎 | Consumer→ClickHouse + CEL |
| 3001 | Agent→Server | 文件事件 (open/write/rename/unlink/chmod) | Agent 内置 EDR 引擎 | Consumer→ClickHouse + CEL |
| 3002 | Agent→Server | 网络事件 (tcp_connect/accept/close, udp_send) | Agent 内置 EDR 引擎 | Consumer→ClickHouse + CEL + 端口扫描检测 |
| 3003 | Agent→Server | DNS 查询事件 (dns_query) | Agent 内置 EDR 引擎 | Consumer→ClickHouse + CEL |
| 3004 | Agent→Server | 内存威胁事件 (memfd_exec/deleted_exe/anonymous_exec) | Agent 内置 EDR 引擎 | Consumer→MySQL + CEL |
| 3010 | Agent→Server | BDE 行为画像快照 (behavior_profile) | Agent 内置 EDR 引擎 | Consumer→BDE 基线引擎 |
| 3005-3009, 3011-3099 | - | **未分配** | - | - |

### 资产采集 (5050-5060) → Kafka: `TopicAsset`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 5050 | Plugin→Server | 进程列表 | Collector 插件 | Consumer→MySQL |
| 5051 | Plugin→Server | 端口/网络监听 | Collector 插件 | Consumer→MySQL |
| 5052 | Plugin→Server | 用户账户 | Collector 插件 | Consumer→MySQL |
| 5053 | Plugin→Server | 软件包 (rpm/deb/pip/npm) | Collector 插件 | Consumer→MySQL |
| 5054 | Plugin→Server | 容器 | Collector 插件 | Consumer→MySQL |
| 5055 | Plugin→Server | 应用程序 | Collector 插件 | Consumer→MySQL |
| 5056 | Plugin→Server | 网卡信息 | Collector 插件 | Consumer→MySQL |
| 5057 | Plugin→Server | 磁盘/卷 | Collector 插件 | Consumer→MySQL |
| 5058 | Plugin→Server | 内核模块 (kmod) | Collector 插件 | Consumer→MySQL |
| 5059 | Plugin→Server | 系统服务 | Collector 插件 | Consumer→MySQL |
| 5060 | Plugin→Server | 定时任务 (cron) | Collector 插件 | Consumer→MySQL |
| 5061-5099 | - | **预留资产扩展**（如 K8s 资源、云实例） | - | - |

> **注意**: 5050-5060 全部占满，新增资产类型从 5061 开始。

### FIM 文件完整性 (6000-6099) → Kafka: `TopicEvents`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 6001 | Plugin→Server | FIM 变更事件 | FIM 插件 | Consumer→MySQL + ClickHouse + CEL |
| 6002 | Plugin→Server | FIM 任务完成信号 | FIM 插件 | Consumer→MySQL |
| 6004 | Plugin→Server | FIM 基线快照（首次扫描） | FIM 插件 | **AC 直处理**（不走 Kafka，涉及事务和去重） |
| 6000, 6003, 6005-6099 | - | **未分配** | - | - |

> **6004 特殊路径**: AC 在 Kafka 发送前拦截 6004，直接调用 `handleFIMBaselineSnapshot()`。
> 基线快照包含完整文件哈希列表，涉及 GORM 事务和去重逻辑，不适合走 Kafka → Consumer。

### 恶意文件扫描 (7000-7099) → Kafka: `TopicScanner`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 7000 | Server→Plugin | 扫描任务下发 | Manager | Scanner 插件 |
| 7001 | Plugin→Server | 扫描结果（威胁检出） | Scanner 插件 | Consumer→MySQL + CEL |
| 7002 | Plugin→Server | 扫描任务完成信号 | Scanner 插件 | Consumer→MySQL |
| 7003 | Server→Plugin | 隔离/删除命令下发 | Manager | Scanner 插件 |
| 7004 | Plugin→Server | 隔离/删除执行结果 | Scanner 插件 | Consumer→MySQL |
| 7005-7099 | - | **未分配** | - | - |

### 基线合规 (8000-8099) → Kafka: `TopicBaseline`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 8000 | Plugin→Server | 基线检查结果 | Baseline 插件 | Consumer→MySQL |
| 8001 | Plugin→Server | 基线扫描任务完成信号 | Baseline 插件 | Consumer→MySQL |
| 8002 | - | **未分配** | - | - |
| 8003 | Plugin→Server | 基线修复结果 | Baseline 插件 | Consumer→MySQL |
| 8004 | Plugin→Server | 基线修复任务完成信号 | Baseline 插件 | Consumer→MySQL |
| 8005-8099 | - | **未分配** | - | - |

### 插件内部心跳 (9000-9001) — **禁止业务使用**

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 9000 | Agent→Plugin | 插件心跳 Ping | Agent | Plugin SDK 自动拦截 |
| 9001 | Plugin→Agent | 插件心跳 Pong | Plugin SDK | Agent 自动拦截 |

> **禁区**: 9000/9001 被插件 SDK (`ReceiveTask()`) 内部拦截，任何业务 DataType
> 使用这两个值都会被吞掉。这是 DataType 9000→9100 冲突事件的根因。

### 漏洞修复 (9100-9299) → Kafka: `TopicRemediation`

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 9100 | Server→Plugin | 修复任务下发 | Manager | Remediation 插件 |
| 9101-9199 | - | **预留修复扩展**（如预检结果、回滚指令） | - | - |
| 9200 | Plugin→Server | 修复执行结果（最终） | Remediation 插件 | Consumer→MySQL |
| 9201 | Plugin→Server | 修复阶段进度 / 漏洞预检结果（precheck_result） | Remediation 插件 | Consumer→MySQL (`WriteRemediationProgress`) |
| 9202-9299 | - | **预留修复结果扩展** | - | - |

### 威胁情报 (9300-9399) — AC→Agent 直接下发（不走 Kafka）

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 9300 | Server→Agent | IOC 数据下发（全量/增量） | AC IOCSyncScheduler | Agent 内置 EDR 引擎（ioc.Store） |
| 9301-9399 | - | **预留威胁情报扩展** | - | - |

### 规则分发 (9400-9499) — AC→Agent 直接下发（不走 Kafka）

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 9400 | Server→Agent | Agent 检测规则下发（YAML 全量推送） | AC RuleSyncScheduler | Agent 内置 EDR 引擎（rule.Manager） |
| 9401-9499 | - | **预留规则分发扩展** | - | - |

> **特殊路径**: 9400 通过 gRPC Task 机制 (ObjectName="edr") 直接推送到 Agent，
> 不经过 Kafka。Agent EDR 引擎接收后将 YAML 规则热加载到内存并持久化到本地规则目录。

> **特殊路径**: 9300 通过 gRPC Task 机制 (ObjectName="edr") 直接推送到 Agent，
> 不经过 Kafka。Agent EDR 引擎接收后加载到内存 HashMap，用于事件实时碰撞检测。

### 控制指令 (9900-9999) → Kafka: `TopicCommandAck` (仅 9999)

| DataType | 方向 | 说明 | 生产者 | 消费者 |
|----------|------|------|--------|--------|
| 9900 | Server→Agent | 任务取消信号 | Manager | Agent 内部处理（不走 Kafka） |
| 9901-9996 | - | **未分配** | - | - |
| 9997 | Server→Agent | 网络阻断/隔离命令 (block_ip/unblock_ip/isolate/release) | Manager/AutoResponder | Agent EDR 引擎 (isolate.Manager) |
| 9998 | Server→Agent | 自动响应命令 (kill_process/quarantine_file) | AutoResponder | Agent EDR 引擎 (rule.ActionExecutor) |
| 9999 | Agent→Server | 命令执行回包 | Agent | Consumer→MySQL |

---

## Kafka Topic 路由映射

路由函数: `internal/server/common/kafka/topics.go` → `RouteDataType()`

| DataType 范围 | Kafka Topic | Retention | Partitions |
|---------------|------------|-----------|------------|
| 1000, 1001 | `mxsec.agent.heartbeat` | 24h | 6 |
| 3000-3099 | `mxsec.agent.ebpf` | 3d | 12 |
| 5050-5060 | `mxsec.agent.asset` | 7d | 6 |
| 6001, 6002 | `mxsec.agent.events` | 72h | 12 |
| 7000-7099 | `mxsec.agent.scanner` | 7d | 6 |
| 8000-8004 | `mxsec.agent.baseline` | 7d | 6 |
| 9100-9299 | `mxsec.agent.remediation` | 7d | 6 |
| 9999 | `mxsec.agent.command-ack` | 7d | 6 |
| **其他** | **`mxsec.agent.heartbeat`（兜底）** | 24h | 6 |

> **兜底陷阱**: 未注册的 DataType 会默认路由到心跳 Topic，被 Consumer 静默忽略。
> 这就是本次 9200 路由缺口的根因 — 新增 DataType 必须同步更新 `RouteDataType()` 和 Consumer `handleMessage()`。

---

## 新增 DataType 检查清单

新增任何 DataType 时，必须完成以下所有步骤：

- [ ] **本文档注册**: 在上方对应模块段落中登记 DataType 值、方向、说明
- [ ] **RouteDataType()**: `internal/server/common/kafka/topics.go` 添加路由规则
- [ ] **Consumer handleMessage()**: `internal/server/consumer/router.go` 添加处理分支
- [ ] **Consumer Writer**: 如需写 MySQL，在 `writer/mysql.go` 添加 WriteXxx 方法
- [ ] **Topic 订阅**: 如新增 Topic，在 Router 的 `topics` 切片中添加订阅
- [ ] **Agent isCompletionSignal()**: 如果是任务完成信号，在 `plugin.go` 中注册
- [ ] **测试验证**: 发送测试消息，确认从 Kafka 到 DB 全链路通过

---

## 处理路径对照表

每个上行 DataType（Plugin/Agent→Server）有两条处理路径：Kafka 路径和 MySQL 直写路径。
Kafka 启用时只走 Kafka 路径，直写路径仅在 Kafka 关闭时兜底。

| DataType | Kafka 路由 | Consumer 处理 | AC 直写 | 说明 |
|----------|-----------|---------------|---------|------|
| 1000 | heartbeat | MySQL+CH+Redis | Y | 完整双路径 |
| 1001 | heartbeat | ClickHouse | - | Kafka-only，指标数据无需持久化到 MySQL |
| 3000-3003 | ebpf | ClickHouse+CEL | - | Kafka-only，时序数据写 ClickHouse（生产者: Agent 内置 EDR 引擎） |
| 3004 | ebpf | MySQL+CEL | - | Kafka-only，内存威胁事件持久化到 MySQL |
| 5050-5060 | asset | MySQL | Y | 完整双路径 |
| 6001 | events | MySQL+CH+CEL | Y | 完整双路径 |
| 6002 | events | MySQL | Y | 完整双路径 |
| 6004 | **AC 拦截** | - | Y | **不走 Kafka**，AC 直接处理（事务+去重） |
| 7001 | scanner | MySQL+CEL | Y | 完整双路径 |
| 7002 | scanner | MySQL | Y | 完整双路径 |
| 7004 | scanner | MySQL | Y | 完整双路径 |
| 8000 | baseline | MySQL | Y | 完整双路径 |
| 8001 | baseline | MySQL | Y | 完整双路径 |
| 8003 | baseline | MySQL | Y | 完整双路径 |
| 8004 | baseline | MySQL | Y | 完整双路径 |
| 9200 | remediation | MySQL | Y | 完整双路径 |
| 9999 | command-ack | MySQL | - | Kafka-only，命令回包 |

> **设计原则**: 写 ClickHouse 的时序数据（1001, 3000-3002）只走 Kafka 路径，
> Kafka 关闭时这些数据不处理（可接受）。6004 因事务复杂性在 AC 侧拦截处理。

---

## 历史冲突事件

| 日期 | DataType | 冲突描述 | 影响 | 根因 |
|------|----------|----------|------|------|
| 2026-05-18 | 9000 | 修复任务 DataType 与插件 SDK 心跳 Ping 冲突 | 任务被 Plugin SDK 拦截吞掉 | 未查阅插件 SDK 保留值 |
| 2026-05-18 | 9200 | 修复结果无 Kafka 路由，落入心跳 Topic | 结果被 Consumer 静默丢弃 | 新增 DataType 未同步更新路由 |
| 2026-05-18 | 6004 | FIM 基线快照在 Kafka 启用时被丢弃 | 基线数据丢失 | AC 直写路径被 Kafka 路径旁路，6004 无 Kafka 路由 |
