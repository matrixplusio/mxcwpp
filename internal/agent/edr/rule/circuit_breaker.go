//go:build linux

package rule

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// cbWindowSize 熔断器滑动窗口大小
	cbWindowSize = 60 * time.Second

	// cbThreshold 窗口内强制动作触发阈值
	cbThreshold = 50

	// cbCooldown 熔断冷却时间：触发后所有强制动作降级为 alert
	cbCooldown = 5 * time.Minute
)

// circuitBreaker 响应动作熔断器
// 防止坏规则或误配导致大量 kill/suspend 动作瘫痪主机
type circuitBreaker struct {
	mu        sync.Mutex
	logger    *zap.Logger
	actions   []time.Time // 滑动窗口内的动作时间戳
	trippedAt time.Time   // 熔断触发时间（零值 = 未熔断）
	tripCount int         // 累计熔断次数
}

// newCircuitBreaker 创建熔断器
func newCircuitBreaker(logger *zap.Logger) *circuitBreaker {
	return &circuitBreaker{
		logger: logger,
	}
}

// Allow 检查是否允许执行强制动作
// 返回 false 表示熔断中，动作应降级为 alert
func (cb *circuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	// 检查是否在冷却期
	if !cb.trippedAt.IsZero() {
		if now.Sub(cb.trippedAt) < cbCooldown {
			return false
		}
		// 冷却期结束 → 恢复
		cb.logger.Info("响应动作熔断器已恢复",
			zap.Duration("cooldown", cbCooldown),
			zap.Int("trip_count", cb.tripCount),
		)
		cb.trippedAt = time.Time{}
		cb.actions = cb.actions[:0]
	}

	// 清理过期记录
	cutoff := now.Add(-cbWindowSize)
	firstValid := 0
	for firstValid < len(cb.actions) && cb.actions[firstValid].Before(cutoff) {
		firstValid++
	}
	if firstValid > 0 {
		cb.actions = cb.actions[firstValid:]
	}

	// 记录本次动作
	cb.actions = append(cb.actions, now)

	// 检查是否超过阈值
	if len(cb.actions) >= cbThreshold {
		cb.trippedAt = now
		cb.tripCount++
		cb.logger.Error("响应动作熔断器触发",
			zap.Int("actions_in_window", len(cb.actions)),
			zap.Int("threshold", cbThreshold),
			zap.Duration("cooldown", cbCooldown),
			zap.Int("trip_count", cb.tripCount),
		)
		return false
	}

	return true
}

// IsTripped 返回当前是否处于熔断状态
func (cb *circuitBreaker) IsTripped() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.trippedAt.IsZero() {
		return false
	}
	return time.Since(cb.trippedAt) < cbCooldown
}

// Stats 返回熔断器统计
func (cb *circuitBreaker) Stats() (tripped bool, tripCount int, windowActions int) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	tripped = !cb.trippedAt.IsZero() && time.Since(cb.trippedAt) < cbCooldown

	// 清理过期记录后计数
	now := time.Now()
	cutoff := now.Add(-cbWindowSize)
	count := 0
	for _, t := range cb.actions {
		if !t.Before(cutoff) {
			count++
		}
	}

	return tripped, cb.tripCount, count
}
