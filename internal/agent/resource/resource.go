// Package resource 提供资源监控功能（CPU、内存、磁盘、网络）
package resource

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// diskIOSnapshot 记录某一时刻的磁盘 I/O 累计值（用于计算两次采样间的 delta）
type diskIOSnapshot struct {
	SectorsRead    uint64
	SectorsWritten uint64
}

// procCPUSnapshot 记录进程级 CPU 采样（/proc/self/stat）
type procCPUSnapshot struct {
	Utime     uint64    // 用户态 jiffies
	Stime     uint64    // 内核态 jiffies
	Timestamp time.Time // 采样时间
}

// Monitor 是资源监控器
type Monitor struct {
	logger      *zap.Logger
	lastCPU     CPUStat
	lastNet     NetStat
	lastDiskIO  map[string]diskIOSnapshot
	lastUpdate  time.Time
	lastProcCPU *procCPUSnapshot // 进程级 CPU 上次采样
}

// CPUStat 是 CPU 统计信息
type CPUStat struct {
	User   uint64
	Nice   uint64
	System uint64
	Idle   uint64
	Iowait uint64
	Total  uint64
}

// MemStat 是内存统计信息
type MemStat struct {
	Total     uint64  // 总内存（KB）
	Available uint64  // 可用内存（KB）
	Used      uint64  // 已使用内存（KB）
	Free      uint64  // 空闲内存（KB）
	Usage     float64 // 使用率（%）
}

// DiskStat 是磁盘统计信息
type DiskStat struct {
	Total     uint64  // 总容量（字节）
	Available uint64  // 可用容量（字节）
	Used      uint64  // 已使用容量（字节）
	Usage     float64 // 使用率（%）
}

// NetStat 是网络统计信息
type NetStat struct {
	BytesSent   uint64 // 发送字节数
	BytesRecv   uint64 // 接收字节数
	PacketsSent uint64 // 发送包数
	PacketsRecv uint64 // 接收包数
}

// ResourceMetrics 是资源指标
type ResourceMetrics struct {
	CPUUsage        float64 // CPU 使用率（%）
	MemUsage        float64 // 内存使用率（%）
	MemTotalBytes   uint64  // 系统总内存（字节）
	DiskUsage       float64 // 磁盘使用率（%）
	DiskReadBytes   uint64  // 距上次采样的磁盘读取字节数
	DiskWriteBytes  uint64  // 距上次采样的磁盘写入字节数
	NetBytesSent    uint64  // 网络发送字节数（累计）
	NetBytesRecv    uint64  // 网络接收字节数（累计）
	AgentCPUUsage   float64 // Agent 进程 CPU 使用率（%）
	AgentMemRSS     uint64  // Agent 进程物理内存 RSS（字节）
	AgentMemPercent float64 // Agent 进程内存占系统内存百分比（%）
	Timestamp       int64   // 时间戳
}

// NewMonitor 创建新的资源监控器
func NewMonitor(logger *zap.Logger) *Monitor {
	return &Monitor{
		logger:     logger,
		lastDiskIO: make(map[string]diskIOSnapshot),
		lastUpdate: time.Now(),
	}
}

// Collect 采集资源指标
func (m *Monitor) Collect() (*ResourceMetrics, error) {
	metrics := &ResourceMetrics{
		Timestamp: time.Now().Unix(),
	}

	// 采集 CPU 使用率
	cpuUsage, err := m.collectCPU()
	if err != nil {
		m.logger.Warn("failed to collect CPU usage", zap.Error(err))
	} else {
		metrics.CPUUsage = cpuUsage
	}

	// 采集内存使用率
	memUsage, memTotalBytes, err := m.collectMemory()
	if err != nil {
		m.logger.Warn("failed to collect memory usage", zap.Error(err))
	} else {
		metrics.MemUsage = memUsage
		metrics.MemTotalBytes = memTotalBytes
	}

	// 采集磁盘使用率
	diskUsage, err := m.collectDisk()
	if err != nil {
		m.logger.Warn("failed to collect disk usage", zap.Error(err))
	} else {
		metrics.DiskUsage = diskUsage
	}

	// 采集磁盘 I/O（距上次采样的 delta 字节数）
	diskReadBytes, diskWriteBytes, err := m.collectDiskIO()
	if err != nil {
		m.logger.Warn("failed to collect disk I/O", zap.Error(err))
	} else {
		metrics.DiskReadBytes = diskReadBytes
		metrics.DiskWriteBytes = diskWriteBytes
	}

	// 采集网络统计
	netBytesSent, netBytesRecv, err := m.collectNetwork()
	if err != nil {
		m.logger.Warn("failed to collect network stats", zap.Error(err))
	} else {
		metrics.NetBytesSent = netBytesSent
		metrics.NetBytesRecv = netBytesRecv
	}

	// 采集 Agent 进程级 CPU 使用率
	agentCPU, err := m.collectProcessCPU()
	if err != nil {
		m.logger.Warn("failed to collect agent CPU usage", zap.Error(err))
	} else {
		metrics.AgentCPUUsage = agentCPU
	}

	// 采集 Agent 进程级内存 RSS
	agentMem, err := m.collectProcessMemory()
	if err != nil {
		m.logger.Warn("failed to collect agent memory usage", zap.Error(err))
	} else {
		metrics.AgentMemRSS = agentMem
		if metrics.MemTotalBytes > 0 {
			metrics.AgentMemPercent = float64(agentMem) / float64(metrics.MemTotalBytes) * 100.0
		}
	}

	return metrics, nil
}

// collectCPU 采集 CPU 使用率
func (m *Monitor) collectCPU() (float64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, fmt.Errorf("failed to read /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, fmt.Errorf("invalid /proc/stat format")
	}

	// 解析 CPU 统计
	var stat CPUStat
	stat.User, _ = strconv.ParseUint(fields[1], 10, 64)
	stat.Nice, _ = strconv.ParseUint(fields[2], 10, 64)
	stat.System, _ = strconv.ParseUint(fields[3], 10, 64)
	stat.Idle, _ = strconv.ParseUint(fields[4], 10, 64)
	stat.Iowait, _ = strconv.ParseUint(fields[5], 10, 64)
	stat.Total = stat.User + stat.Nice + stat.System + stat.Idle + stat.Iowait

	// 计算 CPU 使用率
	now := time.Now()
	elapsed := now.Sub(m.lastUpdate).Seconds()
	if elapsed < 1.0 {
		elapsed = 1.0 // 避免除零
	}

	if m.lastCPU.Total > 0 {
		totalDiff := stat.Total - m.lastCPU.Total
		idleDiff := stat.Idle - m.lastCPU.Idle

		if totalDiff > 0 {
			usage := 100.0 * (1.0 - float64(idleDiff)/float64(totalDiff))
			m.lastCPU = stat
			m.lastUpdate = now
			return usage, nil
		}
	}

	m.lastCPU = stat
	m.lastUpdate = now
	return 0, nil
}

// collectMemory 采集内存使用率，同时返回总内存字节数
func (m *Monitor) collectMemory() (usage float64, totalBytes uint64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var mem MemStat
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}

		switch key {
		case "MemTotal":
			mem.Total = value
		case "MemAvailable":
			mem.Available = value
		case "MemFree":
			mem.Free = value
		}
	}

	if mem.Total == 0 {
		return 0, 0, fmt.Errorf("failed to read memory info")
	}

	if mem.Available > 0 {
		mem.Used = mem.Total - mem.Available
		mem.Usage = 100.0 * float64(mem.Used) / float64(mem.Total)
	} else {
		mem.Used = mem.Total - mem.Free
		mem.Usage = 100.0 * float64(mem.Used) / float64(mem.Total)
	}

	return mem.Usage, mem.Total * 1024, nil // KB → 字节
}

// collectDisk 采集磁盘使用率（根分区）
func (m *Monitor) collectDisk() (float64, error) {
	// 使用 statfs 系统调用获取根分区信息
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, err
	}

	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - available

	usage := 100.0 * float64(used) / float64(total)
	return usage, nil
}

// collectDiskIO 从 /proc/diskstats 采集磁盘 I/O 速率
// 返回距上次采样期间的累计读取/写入字节数
// 只统计物理磁盘（sd、vd、nvme、xvd 前缀），过滤 loop、dm-、ram 等虚拟设备
func (m *Monitor) collectDiskIO() (readBytes, writeBytes uint64, err error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	current := make(map[string]diskIOSnapshot)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// 只保留物理磁盘，过滤分区（如 sda1）和虚拟设备
		if !isPhysicalDisk(name) {
			continue
		}
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		sectorsWritten, _ := strconv.ParseUint(fields[9], 10, 64)
		current[name] = diskIOSnapshot{
			SectorsRead:    sectorsRead,
			SectorsWritten: sectorsWritten,
		}
	}

	// 计算与上次快照的 delta
	for name, snap := range current {
		if prev, ok := m.lastDiskIO[name]; ok {
			var dr, dw uint64
			if snap.SectorsRead >= prev.SectorsRead {
				dr = snap.SectorsRead - prev.SectorsRead
			}
			if snap.SectorsWritten >= prev.SectorsWritten {
				dw = snap.SectorsWritten - prev.SectorsWritten
			}
			readBytes += dr * 512
			writeBytes += dw * 512
		}
	}

	m.lastDiskIO = current
	return readBytes, writeBytes, nil
}

// isPhysicalDisk 判断设备名是否为物理磁盘（排除分区和虚拟设备）
func isPhysicalDisk(name string) bool {
	prefixes := []string{"sd", "vd", "xvd", "hd"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			// 排除分区（如 sda1、sdb2），只保留整盘（如 sda、sdb）
			suffix := strings.TrimPrefix(name, p)
			allAlpha := true
			for _, c := range suffix {
				if c < 'a' || c > 'z' {
					allAlpha = false
					break
				}
			}
			return allAlpha
		}
	}
	// nvme 磁盘：nvme0n1 是整盘，nvme0n1p1 是分区
	if strings.HasPrefix(name, "nvme") {
		return !strings.Contains(name, "p")
	}
	return false
}

// collectNetwork 采集网络统计（累计值）
func (m *Monitor) collectNetwork() (uint64, uint64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var bytesSent, bytesRecv uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 跳过标题行
		if strings.Contains(line, "bytes") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 跳过回环接口
		iface := strings.TrimSuffix(fields[0], ":")
		if strings.HasPrefix(iface, "lo") {
			continue
		}

		// 字段顺序：interface | bytes_recv | packets_recv | ... | bytes_sent | packets_sent | ...
		recv, _ := strconv.ParseUint(fields[1], 10, 64)
		sent, _ := strconv.ParseUint(fields[9], 10, 64)

		bytesRecv += recv
		bytesSent += sent
	}

	// 更新累计值
	m.lastNet.BytesSent = bytesSent
	m.lastNet.BytesRecv = bytesRecv

	return bytesSent, bytesRecv, nil
}

// collectProcessCPU 采集当前进程的 CPU 使用率
// 读取 /proc/self/stat 的 utime+stime（jiffies），两次采样取 delta 计算占比
func (m *Monitor) collectProcessCPU() (float64, error) {
	utime, stime, err := readProcSelfCPU()
	if err != nil {
		return 0, err
	}

	now := time.Now()
	snap := &procCPUSnapshot{Utime: utime, Stime: stime, Timestamp: now}

	if m.lastProcCPU == nil {
		m.lastProcCPU = snap
		return 0, nil
	}

	elapsed := now.Sub(m.lastProcCPU.Timestamp).Seconds()
	if elapsed < 0.5 {
		return 0, nil
	}

	// delta jiffies → 秒，除以经过的墙钟时间，再除以 CPU 核心数得到百分比
	totalJiffies := (utime + stime) - (m.lastProcCPU.Utime + m.lastProcCPU.Stime)
	// Linux 默认 100 jiffies/秒 (USER_HZ)
	cpuSeconds := float64(totalJiffies) / 100.0
	usage := cpuSeconds / elapsed / float64(runtime.NumCPU()) * 100.0
	if usage > 100 {
		usage = 100
	}

	m.lastProcCPU = snap
	return usage, nil
}

// readProcSelfCPU 从 /proc/self/stat 解析 utime 和 stime
func readProcSelfCPU() (utime, stime uint64, err error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	// /proc/self/stat 格式：pid (comm) state ppid ... 第14列=utime 第15列=stime
	// comm 可能包含空格和括号，所以先找最后一个 ')' 的位置
	content := string(data)
	idx := strings.LastIndex(content, ")")
	if idx < 0 {
		return 0, 0, fmt.Errorf("invalid /proc/self/stat format")
	}
	fields := strings.Fields(content[idx+2:]) // 跳过 ") "
	// fields[0]=state, fields[1]=ppid, ..., fields[11]=utime, fields[12]=stime
	if len(fields) < 13 {
		return 0, 0, fmt.Errorf("not enough fields in /proc/self/stat")
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	return utime, stime, nil
}

// collectProcessMemory 采集当前进程的物理内存 RSS
// 读取 /proc/self/status 的 VmRSS 字段（单位 KB，返回字节）
func (m *Monitor) collectProcessMemory() (uint64, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
				if parseErr != nil {
					return 0, parseErr
				}
				return kb * 1024, nil // KB → 字节
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/self/status")
}
