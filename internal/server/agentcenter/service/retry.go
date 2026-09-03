// Package service 提供重试机制
package service

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries int           // 最大重试次数
	Interval   time.Duration // 重试间隔
	Backoff    float64       // 退避倍数（指数退避）
}

// DefaultRetryConfig 默认重试配置
var DefaultRetryConfig = RetryConfig{
	MaxRetries: 3,
	Interval:   time.Second,
	Backoff:    2.0,
}

// RetryFunc 重试函数类型
type RetryFunc func() error

// Retry 执行带重试的操作
func Retry(ctx context.Context, fn RetryFunc, config RetryConfig, logger *zap.Logger) error {
	var lastErr error
	interval := config.Interval

	for i := 0; i <= config.MaxRetries; i++ {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 执行操作
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// 如果不是最后一次重试，等待后重试
		if i < config.MaxRetries {
			logger.Warn("操作失败，准备重试",
				zap.Int("attempt", i+1),
				zap.Int("max_retries", config.MaxRetries),
				zap.Duration("interval", interval),
				zap.Error(err),
			)

			// 等待
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
				// 指数退避
				interval = time.Duration(float64(interval) * config.Backoff)
			}
		}
	}

	return fmt.Errorf("操作失败，已重试 %d 次: %w", config.MaxRetries, lastErr)
}

// RetryWithContext 执行带上下文和重试的操作
func RetryWithContext(ctx context.Context, fn func(context.Context) error, config RetryConfig, logger *zap.Logger) error {
	return Retry(ctx, func() error {
		return fn(ctx)
	}, config, logger)
}
