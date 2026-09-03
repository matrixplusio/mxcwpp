// Package npatch — protect 模式在线阻断 (EDR-2).
//
// observe 模式: 命中 → ringbuf 上报, 流量正常通过 (默认 / 安全)
// protect 模式: 命中 → cgroup_skb 返 SK_DROP 内核态丢包 (高风险)
//
// 启用条件:
//  1. tenant 已通过 6 闸门 admission
//  2. rule 已通过 G6 灰度推送 (默认 1%→10%→100%)
//  3. host_label 不在白名单 (e.g. env=prod 才阻, dev/staging 默认 observe)
//
// CentOS 7 兼容性: cgroup_skb 路径 (kernel 4.10+) 支持 SK_DROP 阻断.
// AF_PACKET v3 路径无法阻断 (用户态收包, 流量已过), 仅上报.
package npatch

import (
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// ProtectMode 阻断决策.
type ProtectMode int

const (
	// ModeObserve 仅观察上报, 不阻断 (默认 + 严格 read-only 哲学)
	ModeObserve ProtectMode = iota
	// ModeProtect 内核态 SK_DROP 阻断 (高风险, 需 admission 通过)
	ModeProtect
)

// ProtectController 单 host 的 protect 模式控制器.
//
// 状态写入 BPF map (cgroup_skb 路径) 让内核态读决策, 或在 AF_PACKET 路径直接读.
type ProtectController struct {
	logger *zap.Logger

	// 全局默认 mode (atomic, 跨 goroutine 可读)
	defaultMode atomic.Int32

	mu sync.RWMutex
	// rule_id → mode 覆盖 (灰度推送时 rule 级控制)
	ruleOverrides map[string]ProtectMode
	// host_label → mode 覆盖 (env=prod 强 protect, dev 强 observe)
	labelOverrides map[string]ProtectMode

	// 命中阻断统计
	blocksTotal     atomic.Uint64
	wouldBlockTotal atomic.Uint64
}

// NewProtectController 构造, 默认 observe.
func NewProtectController(logger *zap.Logger) *ProtectController {
	if logger == nil {
		logger = zap.NewNop()
	}
	pc := &ProtectController{
		logger:         logger,
		ruleOverrides:  make(map[string]ProtectMode),
		labelOverrides: make(map[string]ProtectMode),
	}
	pc.defaultMode.Store(int32(ModeObserve))
	return pc
}

// SetDefaultMode 全局默认.
func (pc *ProtectController) SetDefaultMode(m ProtectMode) {
	pc.defaultMode.Store(int32(m))
	pc.logger.Info("protect default mode set",
		zap.String("mode", m.String()))
}

// SetRuleOverride 单 rule 模式覆盖 (G6 灰度推送配套).
func (pc *ProtectController) SetRuleOverride(ruleID string, m ProtectMode) {
	pc.mu.Lock()
	pc.ruleOverrides[ruleID] = m
	pc.mu.Unlock()
}

// SetLabelOverride host 标签模式覆盖 (env=prod / cluster=staging).
func (pc *ProtectController) SetLabelOverride(label string, m ProtectMode) {
	pc.mu.Lock()
	pc.labelOverrides[label] = m
	pc.mu.Unlock()
}

// Resolve 给定 rule + labels 解出最终 mode.
//
// 优先级 (高→低): host_label > rule > default.
func (pc *ProtectController) Resolve(ruleID string, hostLabels []string) ProtectMode {
	pc.mu.RLock()
	for _, lbl := range hostLabels {
		if m, ok := pc.labelOverrides[lbl]; ok {
			pc.mu.RUnlock()
			return m
		}
	}
	if m, ok := pc.ruleOverrides[ruleID]; ok {
		pc.mu.RUnlock()
		return m
	}
	pc.mu.RUnlock()
	return ProtectMode(pc.defaultMode.Load())
}

// Decide 命中规则时的最终决策 — 同时累计 metrics.
//
// 返回:
//   - shouldBlock: true 才在 cgroup_skb 返 SK_DROP / AF_PACKET 路径忽略阻断
//   - finalMode: 实际生效的模式 (供日志/告警 mode 字段)
func (pc *ProtectController) Decide(ruleID string, hostLabels []string) (shouldBlock bool, finalMode ProtectMode) {
	finalMode = pc.Resolve(ruleID, hostLabels)
	switch finalMode {
	case ModeProtect:
		pc.blocksTotal.Add(1)
		return true, finalMode
	default:
		pc.wouldBlockTotal.Add(1)
		return false, finalMode
	}
}

// Stats 累计.
func (pc *ProtectController) Stats() (blocks, wouldBlock uint64) {
	return pc.blocksTotal.Load(), pc.wouldBlockTotal.Load()
}

// String 调试.
func (m ProtectMode) String() string {
	switch m {
	case ModeProtect:
		return "protect"
	default:
		return "observe"
	}
}

// ResetCounters 给测试用.
func (pc *ProtectController) ResetCounters() {
	pc.blocksTotal.Store(0)
	pc.wouldBlockTotal.Store(0)
}
