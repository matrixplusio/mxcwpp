// Package cache 是 LLMProxy 的 Redis 24h 入参缓存。
//
// 入参 SHA256 -> 响应 JSON,降低 LLM 调用成本。
// 设计文档: docs/llmproxy-design.md §3.4 cache
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultTTL 默认缓存 TTL。
const DefaultTTL = 24 * time.Hour

// DefaultKeyPrefix Redis key 前缀。
const DefaultKeyPrefix = "mxcwpp:llm:cache:"

// Cache 包装 redis client 暴露 Get/Set。
type Cache struct {
	rdb       *redis.Client
	ttl       time.Duration
	keyPrefix string
}

// Config 缓存配置。
type Config struct {
	TTL       time.Duration
	KeyPrefix string
}

// New 构造缓存。
func New(rdb *redis.Client, cfg Config) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = DefaultKeyPrefix
	}
	return &Cache{rdb: rdb, ttl: cfg.TTL, keyPrefix: cfg.KeyPrefix}
}

// Key 根据 (provider, model, payload) 计算缓存 key。
func (c *Cache) Key(provider, model string, payload any) (string, error) {
	pj, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(provider))
	h.Write([]byte(model))
	h.Write(pj)
	return c.keyPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// Get 取缓存; miss 返回 redis.Nil。
func (c *Cache) Get(ctx context.Context, key string, out any) error {
	raw, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// Set 写缓存。
func (c *Cache) Set(ctx context.Context, key string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, raw, c.ttl).Err()
}

// IsMiss 判断错误是否是 cache miss。
func IsMiss(err error) bool {
	return err == redis.Nil
}
