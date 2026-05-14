// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// VolumeHandler 是磁盘采集器
type VolumeHandler struct {
	Logger *zap.Logger
}

// Collect 采集磁盘信息
func (h *VolumeHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var volumes []interface{}

	// 读取 /proc/mounts 获取挂载信息
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/mounts: %w", err)
	}

	lines := strings.Split(string(mounts), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return volumes, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 /proc/mounts 格式：device mount_point file_system options dump pass
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fileSystem := fields[2]

		// 跳过虚拟文件系统
		if h.isVirtualFileSystem(fileSystem) {
			continue
		}

		// 跳过非块设备
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		// 获取磁盘使用情况
		usage, err := h.getDiskUsage(mountPoint)
		if err != nil {
			h.Logger.Debug("failed to get disk usage",
				zap.String("mount_point", mountPoint),
				zap.Error(err))
			continue
		}

		volume := &engine.VolumeAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			Device:        device,
			MountPoint:    mountPoint,
			FileSystem:    fileSystem,
			TotalSize:     usage.TotalSize,
			UsedSize:      usage.UsedSize,
			AvailableSize: usage.AvailableSize,
			UsagePercent:  usage.UsagePercent,
		}

		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// DiskUsage 磁盘使用情况
type DiskUsage struct {
	TotalSize     int64
	UsedSize      int64
	AvailableSize int64
	UsagePercent  float64
}

// getDiskUsage 获取磁盘使用情况
func (h *VolumeHandler) getDiskUsage(path string) (*DiskUsage, error) {
	// 使用 df 命令获取磁盘使用情况
	cmd := exec.Command("df", "-B1", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute df: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid df output")
	}

	// 解析 df 输出：Filesystem 1B-blocks Used Available Use% Mounted on
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return nil, fmt.Errorf("invalid df output format")
	}

	totalSize, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse total size: %w", err)
	}

	usedSize, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse used size: %w", err)
	}

	availableSize, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse available size: %w", err)
	}

	// 计算使用率
	usagePercent := float64(usedSize) / float64(totalSize) * 100

	return &DiskUsage{
		TotalSize:     totalSize,
		UsedSize:      usedSize,
		AvailableSize: availableSize,
		UsagePercent:  usagePercent,
	}, nil
}

// isVirtualFileSystem 判断是否为虚拟文件系统
func (h *VolumeHandler) isVirtualFileSystem(fsType string) bool {
	virtualFS := []string{
		"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup",
		"cgroup2", "pstore", "bpf", "tracefs", "debugfs", "securityfs",
		"hugetlbfs", "mqueue", "overlay", "autofs", "binfmt_misc",
		"rpc_pipefs", "systemd-1", "fusectl", "configfs", "efivarfs",
	}

	for _, vfs := range virtualFS {
		if fsType == vfs {
			return true
		}
	}

	return false
}
