// Package quota 提供租户级 LLM 月度 USD 配额检查与累积。
//
// 设计文档: docs/llmproxy-design.md §3.5 quota
//
// 实现:
//   - Redis key mxsec:llm:tenant:cost:{tenant}:{yyyymm}
//   - INCRBYFLOAT 原子累积成本 (USD)
//   - 32 天 TTL (跨月自动失效)
//   - Pre-check: 调用前先 GET 比对 cap, 超额返回 ErrQuotaExceeded
//   - Post-update: 调用成功后 INCRBYFLOAT 累积
package quota

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultKeyPrefix Redis key 前缀。
const DefaultKeyPrefix = "mxsec:llm:tenant:cost:"

// DefaultTTL Redis key 存活时间。
const DefaultTTL = 32 * 24 * time.Hour

// Config 配置。
type Config struct {
	KeyPrefix string
	TTL       time.Duration
}

// Manager 是 quota 管理器。
type Manager struct {
	rdb       *redis.Client
	keyPrefix string
	ttl       time.Duration
}

// New 构造 quota manager。
func New(rdb *redis.Client, cfg Config) *Manager {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = DefaultKeyPrefix
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	return &Manager{rdb: rdb, keyPrefix: cfg.KeyPrefix, ttl: cfg.TTL}
}

// ErrQuotaExceeded 超过月度配额。
var ErrQuotaExceeded = errors.New("quota: tenant monthly USD exceeded")

// monthlyKey 生成 tenant 月度 key。
func (m *Manager) monthlyKey(tenantID string, t time.Time) string {
	return fmt.Sprintf("%s%s:%s", m.keyPrefix, tenantID, t.UTC().Format("200601"))
}

// PreCheck 预检租户当月累积成本是否超 cap。
//
// Redis 不可用时降级放行 (避免误阻断)。
func (m *Manager) PreCheck(ctx context.Context, tenantID string, capUSD float64) error {
	if capUSD <= 0 || tenantID == "" {
		return nil
	}
	key := m.monthlyKey(tenantID, time.Now())
	used, err := m.rdb.Get(ctx, key).Float64()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return nil // Redis 不可用降级放行
	}
	if used >= capUSD {
		return ErrQuotaExceeded
	}
	return nil
}

// Add 累积调用成本。
func (m *Manager) Add(ctx context.Context, tenantID string, cost float64) error {
	if tenantID == "" || cost <= 0 {
		return nil
	}
	key := m.monthlyKey(tenantID, time.Now())
	if _, err := m.rdb.IncrByFloat(ctx, key, cost).Result(); err != nil {
		return fmt.Errorf("quota: incr: %w", err)
	}
	_ = m.rdb.Expire(ctx, key, m.ttl).Err()
	return nil
}

// CurrentUsage 查询当月已用 USD。
func (m *Manager) CurrentUsage(ctx context.Context, tenantID string) (float64, error) {
	key := m.monthlyKey(tenantID, time.Now())
	used, err := m.rdb.Get(ctx, key).Float64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return used, nil
}
