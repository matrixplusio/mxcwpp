// Package heartbeat 提供心跳上报功能
// 本文件提供主机信息采集函数，用于在心跳中上报磁盘和网卡信息
package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DiskInfo 磁盘信息结构
type DiskInfo struct {
	Device        string  `json:"device"`         // /dev/sda1
	MountPoint    string  `json:"mount_point"`    // /、/home 等
	FileSystem    string  `json:"file_system"`    // ext4、xfs 等
	TotalSize     int64   `json:"total_size"`     // 总大小（字节）
	UsedSize      int64   `json:"used_size"`      // 已用大小（字节）
	AvailableSize int64   `json:"available_size"` // 可用大小（字节）
	UsagePercent  float64 `json:"usage_percent"`  // 使用率（百分比）
}

// NetworkInterfaceInfo 网卡信息结构
type NetworkInterfaceInfo struct {
	InterfaceName string   `json:"interface_name"` // eth0、ens33 等
	MACAddress    string   `json:"mac_address"`    // MAC 地址
	IPv4Addresses []string `json:"ipv4_addresses"` // IPv4 地址列表
	IPv6Addresses []string `json:"ipv6_addresses"` // IPv6 地址列表
	MTU           int      `json:"mtu"`            // 最大传输单元
	State         string   `json:"state"`          // up、down
}

// CollectDiskInfo 采集磁盘信息
// 返回 JSON 字符串，如果采集失败返回空字符串（不返回错误，避免影响心跳上报）
func CollectDiskInfo(ctx context.Context, logger *zap.Logger) string {
	var disks []DiskInfo

	// 读取 /proc/mounts 获取挂载信息
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		logger.Debug("failed to read /proc/mounts", zap.Error(err))
		return ""
	}

	lines := strings.Split(string(mounts), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			logger.Debug("disk collection cancelled")
			return ""
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

		// 跳过虚拟文件系统（但保留 overlay，因为容器环境常用）
		if isVirtualFileSystem(fileSystem) && fileSystem != "overlay" {
			continue
		}

		// 跳过非块设备（但保留根文件系统 / 和 overlay 文件系统）
		if !strings.HasPrefix(device, "/dev/") {
			// 允许 overlay 文件系统（容器环境）和根文件系统
			if fileSystem != "overlay" && mountPoint != "/" {
				continue
			}
			// 对于 overlay 文件系统，使用设备路径 "overlay" 或实际设备路径
			if fileSystem == "overlay" && mountPoint == "/" {
				// 尝试从 overlay 的 lowerdir 或 upperdir 中提取实际设备
				// 如果无法提取，使用 "overlay" 作为设备名
				device = "overlay"
			}
		}

		// 跳过 Docker 容器的 bind mount（挂载点路径包含 /etc/resolv.conf、/etc/hostname 等）
		if strings.Contains(mountPoint, "/etc/resolv.conf") ||
			strings.Contains(mountPoint, "/etc/hostname") ||
			strings.Contains(mountPoint, "/etc/hosts") ||
			strings.Contains(mountPoint, "/var/lib/mxsec-agent") ||
			strings.Contains(mountPoint, "/var/log/mxsec-agent") {
			continue
		}

		// 获取磁盘使用情况
		usage, err := getDiskUsage(mountPoint)
		if err != nil {
			logger.Debug("failed to get disk usage",
				zap.String("mount_point", mountPoint),
				zap.Error(err))
			continue
		}

		disks = append(disks, DiskInfo{
			Device:        device,
			MountPoint:    mountPoint,
			FileSystem:    fileSystem,
			TotalSize:     usage.TotalSize,
			UsedSize:      usage.UsedSize,
			AvailableSize: usage.AvailableSize,
			UsagePercent:  usage.UsagePercent,
		})
	}

	// 序列化为 JSON 字符串
	if len(disks) == 0 {
		return ""
	}

	diskInfoJSON, err := json.Marshal(disks)
	if err != nil {
		logger.Debug("failed to marshal disk info", zap.Error(err))
		return ""
	}

	return string(diskInfoJSON)
}

// CollectNetworkInterfaces 采集网卡信息
// 返回 JSON 字符串，如果采集失败返回空字符串（不返回错误，避免影响心跳上报）
func CollectNetworkInterfaces(ctx context.Context, logger *zap.Logger) string {
	var interfaces []NetworkInterfaceInfo

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Debug("failed to get network interfaces", zap.Error(err))
		return ""
	}

	for _, iface := range ifaces {
		select {
		case <-ctx.Done():
			logger.Debug("network collection cancelled")
			return ""
		default:
		}

		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 获取接口地址
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Debug("failed to get addresses for interface",
				zap.String("interface", iface.Name),
				zap.Error(err))
			continue
		}

		var ipv4Addrs []string
		var ipv6Addrs []string

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.To4() != nil {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			} else {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		}

		// 获取状态
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}

		// 获取 MAC 地址
		macAddress := ""
		if len(iface.HardwareAddr) > 0 {
			macAddress = iface.HardwareAddr.String()
		}

		interfaces = append(interfaces, NetworkInterfaceInfo{
			InterfaceName: iface.Name,
			MACAddress:    macAddress,
			IPv4Addresses: ipv4Addrs,
			IPv6Addresses: ipv6Addrs,
			MTU:           iface.MTU,
			State:         state,
		})
	}

	// 序列化为 JSON 字符串
	if len(interfaces) == 0 {
		return ""
	}

	networkInterfacesJSON, err := json.Marshal(interfaces)
	if err != nil {
		logger.Debug("failed to marshal network interfaces", zap.Error(err))
		return ""
	}

	return string(networkInterfacesJSON)
}

// DiskUsage 磁盘使用情况
type DiskUsage struct {
	TotalSize     int64
	UsedSize      int64
	AvailableSize int64
	UsagePercent  float64
}

// getDiskUsage 获取磁盘使用情况
func getDiskUsage(path string) (*DiskUsage, error) {
	// 使用 df 命令获取磁盘使用情况
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "df", "-B1", path)
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
	var usagePercent float64
	if totalSize > 0 {
		usagePercent = float64(usedSize) / float64(totalSize) * 100
	}

	return &DiskUsage{
		TotalSize:     totalSize,
		UsedSize:      usedSize,
		AvailableSize: availableSize,
		UsagePercent:  usagePercent,
	}, nil
}

// isVirtualFileSystem 判断是否为虚拟文件系统
// 注意：overlay 文件系统在容器环境中是正常的根文件系统，不应该被过滤
func isVirtualFileSystem(fsType string) bool {
	virtualFS := []string{
		"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup",
		"cgroup2", "pstore", "bpf", "tracefs", "debugfs", "securityfs",
		"hugetlbfs", "mqueue", "autofs", "binfmt_misc",
		"rpc_pipefs", "systemd-1", "fusectl", "configfs", "efivarfs",
		// 注意：overlay 已从此列表中移除，因为容器环境中它是正常的根文件系统
	}

	for _, vfs := range virtualFS {
		if fsType == vfs {
			return true
		}
	}

	return false
}
