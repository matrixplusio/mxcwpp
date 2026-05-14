package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
)

var globalRedis *redis.Client

// InitRedis 初始化 Redis 连接，优先级：Sentinel > 单节点
// Sentinel 模式下返回 FailoverClient（自动跟踪 master）
func InitRedis(cfg config.RedisConfig) (*redis.Client, error) {
	poolSize := cfg.PoolSize
	if poolSize == 0 {
		poolSize = 100
	}
	minIdleConns := cfg.MinIdleConns
	if minIdleConns == 0 {
		minIdleConns = 10
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 3 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 3 * time.Second
	}

	var client *redis.Client

	if cfg.Sentinel && len(cfg.SentinelAddrs) > 0 {
		// Sentinel 模式：自动故障转移，生产 HA 推荐
		masterName := cfg.MasterName
		if masterName == "" {
			masterName = "mymaster"
		}
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    masterName,
			SentinelAddrs: cfg.SentinelAddrs,
			Password:      cfg.Password,
			DB:            cfg.DB,
			PoolSize:      poolSize,
			MinIdleConns:  minIdleConns,
			DialTimeout:   dialTimeout,
			ReadTimeout:   readTimeout,
			WriteTimeout:  writeTimeout,
		})
	} else {
		// 单节点模式（开发 / 小规模部署）
		addr := cfg.Addr
		if addr == "" {
			addr = "redis:6379"
		}
		client = redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     cfg.Password,
			DB:           cfg.DB,
			PoolSize:     poolSize,
			MinIdleConns: minIdleConns,
			DialTimeout:  dialTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		mode := "单节点"
		if cfg.Sentinel {
			mode = "Sentinel"
		}
		return nil, fmt.Errorf("Redis %s 连接失败: %w", mode, err)
	}

	globalRedis = client
	return client, nil
}

// GetRedis 获取全局 Redis 客户端（初始化后使用）
func GetRedis() *redis.Client {
	return globalRedis
}

// CloseRedis 关闭 Redis 连接
func CloseRedis() error {
	if globalRedis != nil {
		return globalRedis.Close()
	}
	return nil
}

// RedisClientAdapter 将 go-redis 客户端适配到 biz.RedisClient 接口
type RedisClientAdapter struct {
	client *redis.Client
}

// NewRedisClientAdapter 创建适配器
func NewRedisClientAdapter(client *redis.Client) *RedisClientAdapter {
	return &RedisClientAdapter{client: client}
}

func (a *RedisClientAdapter) Get(ctx context.Context, key string) (string, error) {
	val, err := a.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // key 不存在，返回空字符串而非错误
	}
	return val, err
}

func (a *RedisClientAdapter) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	return a.client.Set(ctx, key, value, expiration).Err()
}

func (a *RedisClientAdapter) Del(ctx context.Context, keys ...string) error {
	return a.client.Del(ctx, keys...).Err()
}

func (a *RedisClientAdapter) Exists(ctx context.Context, key string) (bool, error) {
	n, err := a.client.Exists(ctx, key).Result()
	return n > 0, err
}
