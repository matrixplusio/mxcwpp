// Package canary 提供统一的灰度发布抽象,
// 让"Agent 升级 / 规则推送 / 基线修复 / 漏洞修复 / 病毒处置 / 配置变更"
// 6 类写操作共享同一份"分批 → 健康检查 → 失败回滚"调度逻辑。
//
// 设计动机 (详见 docs/multi-tenant.md §3.5 + ref/01-服务端架构.md §4 P1-3):
//
//	v1: CanaryRollout 仅支持 agent/rule 两类,
//	    基线/漏洞/病毒/配置修改一刀切下发,缺灰度 = "一条命令把全网打挂"。
//
//	v2: 抽 CanaryDriver interface,每类操作实现 driver,
//	    CanaryScheduler 统一调度;新增类型只需注册 driver,不需要改 scheduler。
//
// PR6 仅落"接口 + 注册表 + 5 新 RolloutType + 单元测试",
// 现有 agent_update_scheduler / rule_sync_scheduler 适配在后续 PR。
package canary

import (
	"context"
	"fmt"
	"sync"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// CanaryDriver 是一类灰度发布操作的执行驱动。
//
// 由各业务方实现 (基线/漏洞/病毒/配置), 注册到全局 Registry。
// Scheduler 按 RolloutType 路由到对应 driver。
//
// 实现方约束:
//   - Push 应是幂等的 (同一 stage 重复调用结果一致)
//   - Push 应在 context 取消时及时返回
//   - failureRate 计算应只考虑当前 stage 的 agents,不累计历史 stage
type CanaryDriver interface {
	// Type 返回该 driver 处理的 RolloutType。
	Type() model.RolloutType

	// Push 向指定 agents 下发当前 stage 的操作。
	// 返回值: 成功 / 失败计数。
	Push(ctx context.Context, rollout *model.CanaryRollout, agents []string) (pushed, failed int, err error)

	// HealthCheck 判断当前 stage 健康度。
	// 返回 failureRate (0.0~1.0) 与 readyToAdvance (是否可推进下一 stage)。
	// 典型实现: 查 command-ack Topic 或 Agent 心跳确认率。
	HealthCheck(ctx context.Context, rollout *model.CanaryRollout) (failureRate float64, readyToAdvance bool, err error)

	// Rollback 回滚 (例: 撤回新规则,恢复旧 Agent 版本)。
	// 仅当 failureRate ≥ FailureThreshold 时被调用。
	Rollback(ctx context.Context, rollout *model.CanaryRollout, reason string) error
}

// Registry 是按 RolloutType 索引的 driver 注册表。
//
// 调用方 (Engine / Manager / AC) 启动时通过 Register 注册 driver,
// Scheduler 按 type 查 driver 调度。
type Registry struct {
	mu      sync.RWMutex
	drivers map[model.RolloutType]CanaryDriver
}

// NewRegistry 创建空 Registry。
func NewRegistry() *Registry {
	return &Registry{drivers: make(map[model.RolloutType]CanaryDriver)}
}

// Register 注册 driver。重复注册同一 type 返回错误。
func (r *Registry) Register(d CanaryDriver) error {
	if d == nil {
		return fmt.Errorf("canary: driver must not be nil")
	}
	t := d.Type()
	if t == "" {
		return fmt.Errorf("canary: driver Type() must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.drivers[t]; ok {
		return fmt.Errorf("canary: driver for type %q already registered", t)
	}
	r.drivers[t] = d
	return nil
}

// MustRegister 是 Register 的 panic 版本,用于启动时静态注册。
func (r *Registry) MustRegister(d CanaryDriver) {
	if err := r.Register(d); err != nil {
		panic(err)
	}
}

// Lookup 按 type 查 driver。未注册返回 nil + false。
func (r *Registry) Lookup(t model.RolloutType) (CanaryDriver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[t]
	return d, ok
}

// Types 返回所有已注册的 RolloutType (顺序无关)。
func (r *Registry) Types() []model.RolloutType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.RolloutType, 0, len(r.drivers))
	for t := range r.drivers {
		out = append(out, t)
	}
	return out
}

// DefaultRegistry 是进程全局默认 Registry,
// 便于多包注册同一份 driver 集合 (Engine / Manager / AC 共享)。
var DefaultRegistry = NewRegistry()
