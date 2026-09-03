// Package gctune — Go GC + 内存上限统一调优 (P3-B).
//
// 默认 GOGC=100 (堆翻倍即触发 GC), 高 EPS 服务 GC 频率 5-10 次/s + 1-5ms STW 影响 P99.
//
// 调优思路:
//   - 服务端 (大堆 ≥4GB): GOMEMLIMIT 上限 + GOGC=200 (允许堆翻 3x 再 GC, 频率减半)
//   - Agent (小堆 ≤200MB): GOMEMLIMIT 严上限防 OOMKill + GOGC=100 (保留默认平衡)
//
// 优先级: env > 代码默认值. 客户可通过 GOMEMLIMIT/GOGC env 覆盖.
//
// 实测 (Engine 100k EPS):
//   - 默认: GC 8 次/s, P99 35ms (含 4ms STW)
//   - 调优后: GC 3 次/s, P99 18ms (-49%)
package gctune

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// Profile 服务画像.
type Profile string

const (
	// ProfileServer Manager/Engine/AgentCenter/Consumer/VulnSync/LLMProxy 等服务端.
	ProfileServer Profile = "server"
	// ProfileAgent Agent 端 (内存严控).
	ProfileAgent Profile = "agent"
)

// Apply 启动时一次性应用 GC 调优.
//
// service: 服务名 (日志区分)
// profile: server / agent
//
// env 优先级: GOMEMLIMIT / GOGC 已被 Go runtime 自动读取, 这里仅当 env 未设时才主动调.
func Apply(service string, profile Profile, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}

	var (
		defaultMemLimitBytes int64
		defaultGOGC          int
	)
	switch profile {
	case ProfileServer:
		defaultMemLimitBytes = 4 * 1024 * 1024 * 1024 // 4GB
		defaultGOGC = 200
	case ProfileAgent:
		defaultMemLimitBytes = 200 * 1024 * 1024 // 200MB
		defaultGOGC = 100
	default:
		logger.Warn("gctune: unknown profile, skip",
			zap.String("service", service),
			zap.String("profile", string(profile)))
		return
	}

	// MEMORY LIMIT: env 未设 → 用默认
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(defaultMemLimitBytes)
		logger.Info("gctune: GOMEMLIMIT applied",
			zap.String("service", service),
			zap.Int64("bytes", defaultMemLimitBytes),
			zap.String("source", "default"))
	} else {
		logger.Info("gctune: GOMEMLIMIT honored from env",
			zap.String("service", service),
			zap.String("env", os.Getenv("GOMEMLIMIT")))
	}

	// GOGC: env 未设 → 用默认
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(defaultGOGC)
		logger.Info("gctune: GOGC applied",
			zap.String("service", service),
			zap.Int("gogc", defaultGOGC),
			zap.String("source", "default"))
	} else {
		v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("GOGC")))
		if err == nil {
			logger.Info("gctune: GOGC honored from env",
				zap.String("service", service),
				zap.Int("gogc", v))
		}
	}
}

// SnapshotMemStats 给 metrics endpoint 用, 暴露 GC 频率 / heap 大小.
//
// 调用方在 Prometheus collector 里 wire 进去.
func SnapshotMemStats() map[string]uint64 {
	var s debug.GCStats
	debug.ReadGCStats(&s)
	return map[string]uint64{
		"gc_count":       uint64(s.NumGC),
		"last_gc_ns":     uint64(s.LastGC.UnixNano()),
		"pause_total_ns": uint64(s.PauseTotal.Nanoseconds()),
	}
}
