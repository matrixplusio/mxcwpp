// Package scheduler 是 v2.0 Engine 服务的调度器集合,承担:
//
//   - 告警通知调度 (alert_scheduler): 周期扫 alerts 表挑选 pending 通知派发
//   - 规则同步调度 (rule_sync_scheduler): 规则版本变更后批量推送到 Agent
//   - IOC 同步调度 (ioc_sync_scheduler): 威胁情报 IOC 全量/增量推送
//
// 当前形态 (PR12 占位):
//
//	原 3 个 scheduler 位于 internal/server/agentcenter/scheduler/,
//	通过 transfer.Service 直接持有 Agent 连接池下发命令。
//	该耦合让 AC 既做接入又做"检测产物分发",违反 v2.0 微服务专精原则。
//
//	PR12 仅创建本包占位 + 设计文档,真正搬迁留 Sprint 2:
//	Engine 决策 -> Kafka mxcwpp.engine.command -> AC 订阅 -> 下发 Agent。
//
// 设计文档: docs/engine-design.md / docs/architecture.md §2.4 §2.2
//
// 解耦计划 (Sprint 2 PR):
//
//  1. 定义 EngineCommander interface (向 Agent 下命令的抽象接口)
//  2. AC transfer.Service 实现该 interface (通过 Kafka 消费 -> stream.Send)
//  3. 3 个 scheduler 搬到本包,通过 EngineCommander 下发
//  4. AC 不再依赖 NotificationService / 规则推送业务逻辑
package scheduler

// EngineCommander 是 Engine 下发命令到 Agent 的抽象接口。
//
// 该 interface 在 PR12 阶段未实例化,仅为 Sprint 2 解耦预留契约。
// AC 端 transfer.Service 将实现该 interface (通过 Kafka 订阅
// mxcwpp.engine.command Topic, 转发到 gRPC stream)。
type EngineCommander interface {
	// PushToAgent 把 Engine 产生的命令推送到指定 Agent。
	// 返回 (ok bool, err error) — Agent 离线时 ok=false 不算错误。
	PushToAgent(agentID string, command []byte) (bool, error)

	// PushToAgents 批量推送 (用于规则/IOC 同步)。
	// 返回成功 / 失败计数。
	PushToAgents(agentIDs []string, command []byte) (succeeded, failed int, err error)
}
