// Package leader 提供 VulnSync 服务的 Redis-based Leader Election。
//
// 多副本 VulnSync 部署时,只有 Leader 实际抓取外部数据源,
// 避免重复抓取浪费 API 配额 + Kafka 重复消息。
//
// 实现细节:
//   - 用 Redis SET NX EX key=mxsec:vulnsync:leader ttl=30m
//   - 启动 goroutine 每 5min 续期 (EXPIRE)
//   - 失去 leader 后立即停止所有 source cron
//
// 设计文档: docs/vulnsync-design.md
package leader

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Default 配置
const (
	DefaultKey       = "mxsec:vulnsync:leader"
	DefaultTTL       = 30 * time.Minute
	DefaultRenewTick = 5 * time.Minute
)

// Election 是 Redis-based Leader 选举器。
type Election struct {
	rdb       *redis.Client
	key       string
	value     string // 当前实例的唯一 ID (hostname+pid)
	ttl       time.Duration
	renewTick time.Duration
	logger    *zap.Logger

	isLeader atomic.Bool
}

// Config 配置参数。
type Config struct {
	Key       string        // Redis key (默认 mxsec:vulnsync:leader)
	TTL       time.Duration // leader 锁 TTL (默认 30m)
	RenewTick time.Duration // 续期周期 (默认 5m)
}

// NewElection 构造选举器。instanceID 应该全局唯一 (hostname+pid+uuid)。
func NewElection(rdb *redis.Client, instanceID string, cfg Config, logger *zap.Logger) *Election {
	if cfg.Key == "" {
		cfg.Key = DefaultKey
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.RenewTick <= 0 {
		cfg.RenewTick = DefaultRenewTick
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Election{
		rdb:       rdb,
		key:       cfg.Key,
		value:     instanceID,
		ttl:       cfg.TTL,
		renewTick: cfg.RenewTick,
		logger:    logger,
	}
}

// Run 阻塞运行选举循环,直到 ctx 取消。
//
// 行为:
//  1. 尝试 SET NX EX 取锁
//  2. 取锁成功 → 标记 isLeader=true, 启动续期循环
//  3. 取锁失败 → 等待 TTL/2 后重试
//  4. ctx 取消 → DEL 释放锁, 退出
func (e *Election) Run(ctx context.Context) {
	defer func() {
		// 退出前释放锁 (仅当我们是 leader)
		if e.isLeader.Load() {
			delCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			released, err := e.releaseIfOwner(delCtx)
			if err != nil {
				e.logger.Warn("vulnsync leader release failed", zap.Error(err))
			} else if released {
				e.logger.Info("vulnsync leader 已释放")
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		ok, err := e.tryAcquire(ctx)
		if err != nil {
			e.logger.Error("vulnsync leader try acquire failed", zap.Error(err))
			if !sleepCtx(ctx, e.ttl/2) {
				return
			}
			continue
		}

		if ok {
			e.isLeader.Store(true)
			e.logger.Info("vulnsync 选举为 leader",
				zap.String("instance_id", e.value),
				zap.Duration("ttl", e.ttl),
			)
			e.renewLoop(ctx)
			e.isLeader.Store(false)
			e.logger.Info("vulnsync 失去 leader 身份, 重新选举")
			// 失去 leader 不立即退出, 继续重试
			continue
		}

		// 取锁失败, 等待重试
		if !sleepCtx(ctx, e.ttl/2) {
			return
		}
	}
}

// IsLeader 返回当前是否为 leader。
func (e *Election) IsLeader() bool {
	return e.isLeader.Load()
}

// tryAcquire SET NX EX 尝试取锁 (改 SetArgs, SetNX 在 go-redis v9 标 deprecated).
func (e *Election) tryAcquire(ctx context.Context) (bool, error) {
	res, err := e.rdb.SetArgs(ctx, e.key, e.value, redis.SetArgs{
		Mode: "NX",
		TTL:  e.ttl,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, fmt.Errorf("redis SET NX: %w", err)
	}
	return res == "OK", nil
}

// renewLoop 续期循环,锁失效 / ctx 取消时返回。
func (e *Election) renewLoop(ctx context.Context) {
	ticker := time.NewTicker(e.renewTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, err := e.renewIfOwner(ctx)
			if err != nil {
				e.logger.Warn("vulnsync leader renew error", zap.Error(err))
				return
			}
			if !ok {
				// 锁被其他实例拿走 (我们不再是 owner)
				e.logger.Warn("vulnsync leader lock owner changed, stepping down")
				return
			}
		}
	}
}

// renewIfOwner Lua 脚本: 只有当 value 仍是我们时才续期。
func (e *Election) renewIfOwner(ctx context.Context) (bool, error) {
	const script = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
  return 0
end
`
	res, err := e.rdb.Eval(ctx, script, []string{e.key}, e.value, int(e.ttl/time.Second)).Int()
	if err != nil {
		return false, fmt.Errorf("redis eval renew: %w", err)
	}
	return res == 1, nil
}

// releaseIfOwner Lua 脚本: 只有当 value 仍是我们时才删除。
func (e *Election) releaseIfOwner(ctx context.Context) (bool, error) {
	const script = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`
	res, err := e.rdb.Eval(ctx, script, []string{e.key}, e.value).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

// sleepCtx 在 ctx 取消或 d 到期时返回, 取消返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
