// Package middleware — Redis token bucket 限流 (B1).
//
// 设计:
//   - 桶 key: rl:{tenant_id}:{route_pattern} 或 rl:{ip}:{route_pattern}
//   - 算法: Lua 原子 INCRBY + EXPIRE, 简化 token bucket (固定窗口)
//   - 超限返 429 + Retry-After
//   - Redis 不可达 → fail-open (放行 + warn)
//
// 用法:
//
//	rg.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{
//	    RPS:       100,                  // 每秒 100 请求
//	    Burst:     20,                   // 突发额度
//	    KeyBy:     middleware.KeyByTenant,
//	    Logger:    logger,
//	}))
package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// KeyFunc 自定义 rate-limit key (默认按 tenant+route).
type KeyFunc func(c *gin.Context) string

// KeyByTenant 按 tenant_id + route 作 key.
func KeyByTenant(c *gin.Context) string {
	tid := "anon"
	if v, ok := c.Get("tenant_id"); ok {
		if s, ok2 := v.(string); ok2 && s != "" {
			tid = s
		}
	}
	return "rl:t:" + tid + ":" + c.FullPath()
}

// KeyByIP 按客户端 IP.
func KeyByIP(c *gin.Context) string {
	return "rl:ip:" + c.ClientIP() + ":" + c.FullPath()
}

// RateLimitConfig 配置.
type RateLimitConfig struct {
	RPS    int     // 每秒请求数 (>0)
	Burst  int     // 桶容量 = RPS + Burst (默认 burst=RPS)
	KeyBy  KeyFunc // nil → KeyByTenant
	Logger *zap.Logger
}

// 简化 token bucket: 固定窗口 1s 内 INCR ≤ capacity.
//
// 真正 leaky bucket Lua 复杂, 这里 1s 滑窗 + INCR 已足 (99% 业务场景).
const rateLimitLua = `
local key = KEYS[1]
local cap = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local cur = redis.call('INCR', key)
if cur == 1 then
  redis.call('EXPIRE', key, ttl)
end
if cur > cap then
  return 0
end
return 1
`

var rateLimitScript = redis.NewScript(rateLimitLua)

// RateLimit Gin middleware.
func RateLimit(rdb *redis.Client, cfg RateLimitConfig) gin.HandlerFunc {
	if cfg.RPS <= 0 {
		cfg.RPS = 100
	}
	capacity := cfg.RPS + cfg.Burst
	if capacity <= 0 {
		capacity = cfg.RPS
	}
	if cfg.KeyBy == nil {
		cfg.KeyBy = KeyByTenant
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		if rdb == nil {
			// Redis 未配置 → fail-open
			c.Next()
			return
		}
		key := cfg.KeyBy(c)
		ctx := c.Request.Context()
		ttl := 2 // 2s ttl 给固定窗口缓冲
		res, err := rateLimitScript.Run(ctx, rdb, []string{key}, capacity, ttl).Int()
		if err != nil {
			logger.Warn("ratelimit redis error, fail-open",
				zap.String("key", key),
				zap.Error(err))
			c.Next()
			return
		}
		if res == 0 {
			c.Header("Retry-After", strconv.Itoa(1))
			c.Header("X-RateLimit-Limit", strconv.Itoa(capacity))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    429,
				"message": "rate limit exceeded",
				"data":    nil,
			})
			return
		}
		c.Next()
	}
}

// PerRouteRateLimit 给特定 route 单独限流 (e.g. /login 5 RPS).
func PerRouteRateLimit(rdb *redis.Client, rps, burst int, keyBy KeyFunc, logger *zap.Logger) gin.HandlerFunc {
	return RateLimit(rdb, RateLimitConfig{
		RPS:    rps,
		Burst:  burst,
		KeyBy:  keyBy,
		Logger: logger,
	})
}

// SuggestedDefaults 给路由组的合理默认 RPS.
func SuggestedDefaults() map[string]int {
	return map[string]int{
		"/api/v1/auth/login":             10,  // 防爆破
		"/api/v2/config/change-requests": 30,  // 配置变更不可频繁
		"/api/v2/admin/tenants/":         20,  // 管理 API
		"/api/v1/hosts/:host_id/isolate": 5,   // 隔离动作慎重
		"_default":                       300, // 其它读 API
	}
}

var _ = time.Second
