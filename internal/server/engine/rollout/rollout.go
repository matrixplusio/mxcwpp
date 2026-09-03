// Package rollout — 规则灰度推送 (B6).
//
// 给检测规则按 host_id 哈希分桶, 渐进式启用:
//
//	rollout=10%  → 仅 hash(host_id) % 100 < 10 的主机命中此规则
//	rollout=100% → 所有主机命中 (等同全量启用)
//
// 配合 mode/G6 闸门做安全发布:
//
//	新规则上线 → rollout=1% (canary)
//	24h 观察无误报 → rollout=10%
//	1 周稳定 → rollout=100%
//
// 数据模型: rule_rollouts 表 (rule_id, tenant_id, percent, started_at)
// 命中检查: IsActiveForHost(ruleID, tenantID, hostID).
package rollout

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// State 单条 rollout 配置.
type State struct {
	RuleID    string
	TenantID  string
	Percent   int
	StartedAt time.Time
}

// Resolver 内存缓存 rollout 状态, 30s 刷新.
type Resolver struct {
	db       *gorm.DB
	logger   *zap.Logger
	interval time.Duration

	mu    sync.RWMutex
	cache map[string]State // key: tenant_id + "|" + rule_id
}

// NewResolver 构造.
func NewResolver(db *gorm.DB, logger *zap.Logger) *Resolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Resolver{
		db:       db,
		logger:   logger,
		interval: 30 * time.Second,
		cache:    map[string]State{},
	}
}

// Start 阻塞循环 (在 Engine 启动时 go r.Start(ctx)).
func (r *Resolver) Start(ctx context.Context) {
	r.refresh(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh(ctx)
		}
	}
}

func (r *Resolver) refresh(ctx context.Context) {
	type row struct {
		RuleID    string    `gorm:"column:rule_id"`
		TenantID  string    `gorm:"column:tenant_id"`
		Percent   int       `gorm:"column:percent"`
		StartedAt time.Time `gorm:"column:started_at"`
	}
	var rows []row
	if err := r.db.WithContext(ctx).
		Table("rule_rollouts").
		Find(&rows).Error; err != nil {
		// 表不存在或查失败 → 缓存清空 = 全部走 100% 默认
		r.logger.Debug("rule_rollouts refresh", zap.Error(err))
		return
	}
	next := make(map[string]State, len(rows))
	for _, x := range rows {
		next[x.TenantID+"|"+x.RuleID] = State(x)
	}
	r.mu.Lock()
	r.cache = next
	r.mu.Unlock()
}

// IsActiveForHost 决定规则是否对该主机生效.
//
// 算法:
//   - 无 rollout 记录 → 默认 100% 启用 (向后兼容)
//   - 有记录 percent=0 → 全停 (紧急关停)
//   - 有记录 percent=p → hash32(rule+host) % 100 < p 才命中
func (r *Resolver) IsActiveForHost(tenantID, ruleID, hostID string) bool {
	r.mu.RLock()
	s, ok := r.cache[tenantID+"|"+ruleID]
	r.mu.RUnlock()
	if !ok {
		return true
	}
	if s.Percent <= 0 {
		return false
	}
	if s.Percent >= 100 {
		return true
	}
	return hashBucket(ruleID, hostID) < s.Percent
}

// Get 取 rollout 状态 (UI 显示用).
func (r *Resolver) Get(tenantID, ruleID string) (State, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.cache[tenantID+"|"+ruleID]
	return s, ok
}

// hashBucket 返回 [0, 100) 的桶号.
func hashBucket(ruleID, hostID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ruleID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(hostID))
	return int(h.Sum32() % 100)
}
