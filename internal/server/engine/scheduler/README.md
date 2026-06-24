# Engine Schedulers (PR12 占位 + Sprint 2 迁移规划)

> **当前状态**:仅占位 + interface + 设计文档。实际 scheduler 仍在 `internal/server/agentcenter/scheduler/` 下运行。
>
> **迁移目标**:Sprint 2 通过 Kafka 解耦把 3 个 scheduler 从 AC 迁过来。

---

## 1. 为何 PR12 不直接搬迁

3 个 scheduler 当前直接持有 `transfer.Service`(Agent 连接池),通过 `stream.Send` 推送命令:

```
AC scheduler.PushAgentUpdate(agents)
  └─→ transfer.Service.GetStream(agentID)
       └─→ stream.Send(Command)
```

直接搬到 Engine 会:
- Engine 反向 import AC `transfer` 包(违反 v2.0 微服务边界)
- 或者 Engine 也启动 Agent 连接池(违反单一职责)
- 都不符合"Engine 做决策,AC 做接入"的专精化原则

---

## 2. Sprint 2 迁移设计 (Kafka 解耦)

```
Engine 决策 (调度器)
   │
   │ Kafka Produce
   v
mxcwpp.engine.command  ─→ AC 订阅
                         │
                         v
                      transfer.Service
                         │
                         v
                      Agent (gRPC stream)
```

### 2.1 数据流

```
Engine.RuleSyncScheduler
  └─→ kafka.Produce(Topic="mxcwpp.engine.command", Key=agent_id, Value=Command{...})

AC.CommandConsumer (订阅 mxcwpp-ac-command CG)
  └─→ 解码 Command
       └─→ transfer.Service.PushToAgent(agent_id, command)
```

### 2.2 Topic 设计

新增 `mxcwpp.engine.command` Topic (待 PR 在 `docs/datatype-allocation.md` 登记):

| 字段 | 值 |
|------|------|
| DataType | 11800-11899 (Engine→AC 命令预留段) |
| Partitions | 12 |
| Retention | 24h |
| Partition Key | `{tenant_id}:{agent_id}` |
| 上游 | Engine (本包 scheduler) |
| 下游 | AC `command_consumer.go` |

### 2.3 EngineCommander interface (已在 doc.go 定义)

```go
type EngineCommander interface {
    PushToAgent(agentID string, command []byte) (bool, error)
    PushToAgents(agentIDs []string, command []byte) (succeeded, failed int, err error)
}
```

AC 端实现:`internal/server/agentcenter/command_consumer/kafka_consumer.go` (Sprint 2 新增)

---

## 3. 迁移路线 (Sprint 2 PR 拆解)

| PR | 范围 | 依赖 |
|----|------|------|
| Sprint 2 PR1 | 新增 `mxcwpp.engine.command` Topic + DataType 登记 | - |
| Sprint 2 PR2 | AC `command_consumer` 实现 EngineCommander interface | PR1 |
| Sprint 2 PR3 | `alert_scheduler` 迁 engine/scheduler + AlarmNotifier 解耦 biz | PR2 |
| Sprint 2 PR4 | `rule_sync_scheduler` 迁 engine/scheduler | PR2 |
| Sprint 2 PR5 | `ioc_sync_scheduler` 迁 engine/scheduler | PR2 |
| Sprint 2 PR6 | AC scheduler 目录瘦身,移除 3 个文件 | PR3/4/5 |

---

## 4. 受影响的代码 (Sprint 2)

### 4.1 AC 侧

- `internal/server/agentcenter/scheduler/alert_scheduler.go` → 删
- `internal/server/agentcenter/scheduler/rule_sync_scheduler.go` → 删
- `internal/server/agentcenter/scheduler/ioc_sync_scheduler.go` → 删
- `internal/server/agentcenter/setup/init.go` → 删 scheduler 启动代码
- `internal/server/agentcenter/init/init.go` → 同上
- `internal/server/agentcenter/command_consumer/kafka_consumer.go` → 新增 (Sprint 2)

### 4.2 Engine 侧

- `internal/server/engine/scheduler/alert_scheduler.go` → 新 (迁自 AC)
- `internal/server/engine/scheduler/rule_sync_scheduler.go` → 新
- `internal/server/engine/scheduler/ioc_sync_scheduler.go` → 新
- `cmd/server/engine/main.go` → 启动 3 scheduler + Kafka producer

### 4.3 Manager 侧 (Notifier 解耦)

- `alert_scheduler` 当前依赖 `biz.NotificationService`,需通过类似 PR9 的 `AlarmNotifier` interface 解耦
- `internal/server/engine/scheduler/notifier.go` → 新 (interface 定义)
- `internal/server/manager/biz/scheduler_notifier.go` → 新 (adapter,类似 KubeAlarmNotifier)

---

## 5. 风险与缓解

| 风险 | 缓解 |
|------|------|
| Kafka 延迟引入命令下发延迟 | 测试场景下 P95 ≤ 100ms,生产可接受 |
| 命令丢失 (Kafka broker 故障) | ConsumerGroup 自动 rebalance + DLQ |
| Engine 与 AC 部署分离后 IOC/规则推送链路变长 | 用 OTel trace 串联 Engine→Kafka→AC→Agent 全链路 |
| AC scheduler 删除时漏改 setup/init.go | PR6 必须配 grep 检查所有 scheduler refs |

---

## 6. 验收 (Sprint 2 完成时)

- [ ] AC `scheduler/` 目录只剩 `canary / heartbeat_timeout / task_timeout / plugin_update / agent_update / agent_restart` 等 AC 自身职责的 scheduler
- [ ] Engine `scheduler/` 目录含 `alert / rule_sync / ioc_sync` 3 个
- [ ] `mxcwpp.engine.command` Topic 在 docs/datatype-allocation.md 登记
- [ ] EngineCommander interface 有真实 AC 实现 + 单元测试
- [ ] 端到端测试:Engine 推规则 → AC 收 Kafka → Agent gRPC 收到 → 应用规则
- [ ] Prometheus 指标:engine_command_pushed_total / ac_command_consumed_total / agent_command_applied_total 全链路对账
