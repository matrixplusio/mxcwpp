// Package mode 提供 v2.0 observe/protect 双运行模式的状态机与决策抽象。
//
// 设计文档: docs/operating-modes.md
//
// 核心约束:
//   - 默认 observe (监听优先,符合产品哲学)
//   - 切换到 protect 需要 6 门槛准入 (G1-G6)
//   - 4 级覆盖优先级: 规则级 > 主机标签级 > 租户级 > 全局默认
//
// 工程位置: common/mode 是 Engine/Manager/AC 等多服务共享的运行时决策点,
//
//	所有"是否真执行 action"的检查都走 mode.Should(*).
package mode

import (
	"fmt"
	"strings"
	"sync"
)

// Mode 运行模式。
type Mode string

const (
	Observe Mode = "observe" // 默认: 仅产告警,would_action 标注预期
	Protect Mode = "protect" // 真执行处置 (IP 封禁/PAM/kill/quarantine)
)

// IsValid 判断字符串是否合法 Mode。
func (m Mode) IsValid() bool {
	return m == Observe || m == Protect
}

// String 满足 Stringer。
func (m Mode) String() string { return string(m) }

// Decision 是一次 mode 决策的结果。
type Decision struct {
	Mode   Mode   // observe / protect
	Source string // global / tenant / host_label / rule (谁决定的)
	Reason string // 文档化原因, 写入 audit
}

// Scope 是配置查询的范围。
type Scope struct {
	TenantID   string
	HostLabels map[string]string // host_id 关联的标签
	RuleID     string            // 规则 ID
}

// Resolver 是运行时 mode 查询接口。
//
// 实现方持有 tenants/host_labels/rules 的内存索引,
// 按 4 级覆盖优先级返回 Decision。
type Resolver interface {
	Resolve(scope Scope) Decision
}

// MemoryResolver 是内存版 Resolver, 启动时由 Manager 注入配置。
type MemoryResolver struct {
	mu             sync.RWMutex
	defaultMode    Mode
	tenantModes    map[string]Mode // tenant_id -> mode
	hostLabelModes []hostLabelRule // 按声明顺序匹配
	ruleModes      map[string]Mode // rule_id -> mode
}

type hostLabelRule struct {
	TenantID string
	Label    string // "key=value"
	Mode     Mode
}

// NewMemoryResolver 构造内存 resolver, 默认全局 observe。
func NewMemoryResolver(defaultMode Mode) *MemoryResolver {
	if !defaultMode.IsValid() {
		defaultMode = Observe
	}
	return &MemoryResolver{
		defaultMode: defaultMode,
		tenantModes: make(map[string]Mode),
		ruleModes:   make(map[string]Mode),
	}
}

// SetTenant 设置 tenant-level mode。
func (r *MemoryResolver) SetTenant(tenantID string, m Mode) error {
	if tenantID == "" {
		return fmt.Errorf("mode: tenant_id required")
	}
	if !m.IsValid() {
		return fmt.Errorf("mode: invalid mode %q", m)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenantModes[tenantID] = m
	return nil
}

// SetHostLabel 设置主机标签级 mode (按声明顺序匹配, 先匹配的胜)。
func (r *MemoryResolver) SetHostLabel(tenantID, label string, m Mode) error {
	if !m.IsValid() {
		return fmt.Errorf("mode: invalid mode %q", m)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostLabelModes = append(r.hostLabelModes, hostLabelRule{
		TenantID: tenantID,
		Label:    label,
		Mode:     m,
	})
	return nil
}

// SetRule 设置规则级 mode (最高优先级)。
func (r *MemoryResolver) SetRule(ruleID string, m Mode) error {
	if ruleID == "" {
		return fmt.Errorf("mode: rule_id required")
	}
	if !m.IsValid() {
		return fmt.Errorf("mode: invalid mode %q", m)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ruleModes[ruleID] = m
	return nil
}

// Resolve 按 4 级覆盖优先级返回决策。
//
// 优先级: 规则级 > 主机标签级 > 租户级 > 全局默认 (docs/operating-modes.md §4)
func (r *MemoryResolver) Resolve(scope Scope) Decision {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. 规则级 (最高)
	if scope.RuleID != "" {
		if m, ok := r.ruleModes[scope.RuleID]; ok {
			return Decision{Mode: m, Source: "rule", Reason: "规则级覆盖 rule_id=" + scope.RuleID}
		}
	}

	// 2. 主机标签级
	if scope.TenantID != "" && len(scope.HostLabels) > 0 {
		for _, lr := range r.hostLabelModes {
			if lr.TenantID != "" && lr.TenantID != scope.TenantID {
				continue
			}
			if matchLabel(lr.Label, scope.HostLabels) {
				return Decision{Mode: lr.Mode, Source: "host_label",
					Reason: "主机标签匹配 " + lr.Label}
			}
		}
	}

	// 3. 租户级
	if scope.TenantID != "" {
		if m, ok := r.tenantModes[scope.TenantID]; ok {
			return Decision{Mode: m, Source: "tenant",
				Reason: "租户级 tenant_id=" + scope.TenantID}
		}
	}

	// 4. 全局默认
	return Decision{Mode: r.defaultMode, Source: "global", Reason: "全局默认"}
}

// matchLabel 简单 "key=value" 精确匹配。
func matchLabel(spec string, labels map[string]string) bool {
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		return false
	}
	v, ok := labels[parts[0]]
	return ok && v == parts[1]
}

// ShouldEnforce 返回 Decision.Mode == Protect 时 true (动作类响应允许执行)。
//
// 业务层常用形式:
//
//	if !mode.ShouldEnforce(resolver.Resolve(scope)) {
//	    // observe 模式: 仅记录 would_action,不下发
//	    return
//	}
//	// protect 模式: 真执行 action
func ShouldEnforce(d Decision) bool {
	return d.Mode == Protect
}
