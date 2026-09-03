// Package gctune — Agent 端 GC 调优 (P3-B).
//
// Agent 内存严控: 默认 200MB 上限防 OOMKill, GOGC=100 保留平衡 (Agent 不是高频
// 大堆服务).
//
// env 覆盖: GOMEMLIMIT / GOGC 优先级最高 (Go runtime 自动读).
package gctune

import (
	"os"
	"runtime/debug"

	"go.uber.org/zap"
)

const (
	// defaultMemLimitBytes Agent 默认内存上限 200MB.
	defaultMemLimitBytes int64 = 200 * 1024 * 1024
	// defaultGOGC Agent 默认 GC 触发阈值.
	defaultGOGC = 100
)

// Apply Agent 启动时调一次.
func Apply(logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(defaultMemLimitBytes)
		logger.Info("gctune: GOMEMLIMIT applied",
			zap.Int64("bytes", defaultMemLimitBytes),
			zap.String("source", "default"))
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(defaultGOGC)
		logger.Info("gctune: GOGC applied",
			zap.Int("gogc", defaultGOGC),
			zap.String("source", "default"))
	}
}
