//go:build !linux

package plugin

import (
	"encoding/json"

	"go.uber.org/zap"
)

// ResourceLimits 插件资源限制配置
type ResourceLimits struct {
	MaxMemoryMB   uint64 `json:"max_memory_mb"`
	MaxNoFile     uint64 `json:"max_nofile"`
	MaxCPUSeconds uint64 `json:"max_cpu_seconds"`
}

// parseResourceLimits 从 Config.Detail JSON 解析资源限制
func parseResourceLimits(detail string) ResourceLimits {
	defaults := ResourceLimits{MaxMemoryMB: 512, MaxNoFile: 1024}
	if detail == "" {
		return defaults
	}
	var parsed struct {
		ResourceLimits *ResourceLimits `json:"resource_limits"`
	}
	if err := json.Unmarshal([]byte(detail), &parsed); err != nil || parsed.ResourceLimits == nil {
		return defaults
	}
	limits := *parsed.ResourceLimits
	if limits.MaxMemoryMB == 0 {
		limits.MaxMemoryMB = defaults.MaxMemoryMB
	}
	if limits.MaxNoFile == 0 {
		limits.MaxNoFile = defaults.MaxNoFile
	}
	return limits
}

// applyResourceLimits 非 Linux 平台不支持 prlimit
func (m *Manager) applyResourceLimits(pid int, limits ResourceLimits) {
	m.logger.Warn("resource limits not supported on this platform",
		zap.Int("pid", pid))
}
