//go:build linux

package plugin

import (
	"encoding/json"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

// ResourceLimits 插件资源限制配置
type ResourceLimits struct {
	// RLIMIT_AS（虚拟地址空间限制），默认 0 = 不限制
	// 注意：Go runtime 启动时预留大量虚拟内存（远超实际使用量），
	// 设置过低（如 512MB）会导致 Go 进程立即崩溃。
	// 如需限制，建议至少 4096MB。生产环境推荐用 cgroup memory limit 代替。
	MaxMemoryMB   uint64 `json:"max_memory_mb"`
	MaxNoFile     uint64 `json:"max_nofile"`      // RLIMIT_NOFILE，默认 1024
	MaxCPUSeconds uint64 `json:"max_cpu_seconds"` // RLIMIT_CPU，默认 0(不限)
}

// defaultResourceLimits 返回默认资源限制
func defaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxMemoryMB: 0, // 默认不限制虚拟地址空间（Go 程序不适合 RLIMIT_AS）
		MaxNoFile:   1024,
	}
}

// parseResourceLimits 从 Config.Detail JSON 解析资源限制
func parseResourceLimits(detail string) ResourceLimits {
	defaults := defaultResourceLimits()
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
	// 未配置的字段使用默认值
	if limits.MaxMemoryMB == 0 {
		limits.MaxMemoryMB = defaults.MaxMemoryMB
	}
	if limits.MaxNoFile == 0 {
		limits.MaxNoFile = defaults.MaxNoFile
	}
	return limits
}

// rlimit64 对应内核的 struct rlimit64
type rlimit64 struct {
	Cur uint64
	Max uint64
}

// setPrlimit 调用 prlimit64 设置进程资源限制
func setPrlimit(pid, resource int, soft, hard uint64) error {
	lim := rlimit64{Cur: soft, Max: hard}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRLIMIT64,
		uintptr(pid),
		uintptr(resource),
		uintptr(unsafe.Pointer(&lim)),
		0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// Linux resource constants
const (
	rlimitAS     = 9 // RLIMIT_AS (address space / virtual memory)
	rlimitNOFILE = 7 // RLIMIT_NOFILE
	rlimitCPU    = 0 // RLIMIT_CPU
)

// applyResourceLimits 对指定 PID 应用资源限制
func (m *Manager) applyResourceLimits(pid int, limits ResourceLimits) {
	// RLIMIT_AS（虚拟内存限制）— 仅在显式配置时设置
	// Go runtime 启动时会预留大量虚拟地址空间，RLIMIT_AS 过低会导致进程崩溃
	if limits.MaxMemoryMB > 0 {
		memBytes := limits.MaxMemoryMB * 1024 * 1024
		if err := setPrlimit(pid, rlimitAS, memBytes, memBytes); err != nil {
			m.logger.Warn("failed to set RLIMIT_AS",
				zap.Int("pid", pid),
				zap.Uint64("limit_mb", limits.MaxMemoryMB),
				zap.Error(err))
		} else {
			m.logger.Info("RLIMIT_AS set",
				zap.Int("pid", pid),
				zap.Uint64("limit_mb", limits.MaxMemoryMB))
		}
	}

	// RLIMIT_NOFILE（文件描述符数量）
	if err := setPrlimit(pid, rlimitNOFILE, limits.MaxNoFile, limits.MaxNoFile); err != nil {
		m.logger.Warn("failed to set RLIMIT_NOFILE",
			zap.Int("pid", pid),
			zap.Uint64("limit", limits.MaxNoFile),
			zap.Error(err))
	} else {
		m.logger.Info("RLIMIT_NOFILE set",
			zap.Int("pid", pid),
			zap.Uint64("limit", limits.MaxNoFile))
	}

	// RLIMIT_CPU（可选，默认不限制）
	if limits.MaxCPUSeconds > 0 {
		if err := setPrlimit(pid, rlimitCPU, limits.MaxCPUSeconds, limits.MaxCPUSeconds); err != nil {
			m.logger.Warn("failed to set RLIMIT_CPU",
				zap.Int("pid", pid),
				zap.Uint64("limit_seconds", limits.MaxCPUSeconds),
				zap.Error(err))
		} else {
			m.logger.Info("RLIMIT_CPU set",
				zap.Int("pid", pid),
				zap.Uint64("limit_seconds", limits.MaxCPUSeconds))
		}
	}
}
