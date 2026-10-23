// Package heartbeat 提供心跳上报功能
package heartbeat

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/agent/config"
	"github.com/matrixplusio/mxcwpp/internal/agent/resource"
	agentrt "github.com/matrixplusio/mxcwpp/internal/agent/runtime"
	"github.com/matrixplusio/mxcwpp/internal/agent/transport"
)

// Manager 是心跳管理器
type Manager struct {
	cfg         *config.Config
	logger      *zap.Logger
	transport   *transport.Manager
	agentID     string
	startTime   time.Time          // Agent 启动时间
	pluginMgr   PluginStatusGetter // 插件管理器接口（用于获取插件状态）
	edrEngine   EDRStatusGetter    // EDR 引擎状态接口（可选）
	resourceMon *resource.Monitor  // 资源监控器
}

// PluginStatusGetter 是插件状态获取接口（避免循环依赖）
type PluginStatusGetter interface {
	GetAllPluginStats() map[string]interface{}
}

// EDRStatusGetter 是 EDR 引擎状态获取接口（避免循环依赖）
type EDRStatusGetter interface {
	GetEDRMode() string
	GetEDRCapabilities() []string
	GetEDRHookType() string
	GetEDRStats() (forwarded, dropped uint64)
	RulesVersion() string
	RulesCount() int
	RulesMatched() uint64
	IOCVersion() string
	IOCCount() int
	IOCMatched() uint64
	YARAAvailable() bool
	YARAStats() (scanned, matched uint64)
	ContainerRuntime() string
}

// NewManager 创建新的心跳管理器
func NewManager(cfg *config.Config, logger *zap.Logger, transportMgr *transport.Manager, agentID string, pluginMgr PluginStatusGetter, edrEngine EDRStatusGetter) *Manager {
	return &Manager{
		cfg:         cfg,
		logger:      logger,
		transport:   transportMgr,
		agentID:     agentID,
		startTime:   time.Now(),
		pluginMgr:   pluginMgr,
		edrEngine:   edrEngine,
		resourceMon: resource.NewMonitor(logger),
	}
}

// Startup 启动心跳模块
func Startup(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config, logger *zap.Logger, transportMgr *transport.Manager, agentID string, pluginMgr PluginStatusGetter, edrEngine EDRStatusGetter) {
	defer wg.Done()

	mgr := NewManager(cfg, logger, transportMgr, agentID, pluginMgr, edrEngine)

	currentInterval := cfg.GetHeartbeatInterval()
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	// 立即发送一次心跳
	mgr.sendHeartbeat()

	for {
		select {
		case <-ctx.Done():
			logger.Info("heartbeat module shutting down")
			return
		case <-ticker.C:
			mgr.sendHeartbeat()

			// 检查心跳间隔是否被 Server 远程更新
			newInterval := cfg.GetHeartbeatInterval()
			if newInterval != currentInterval {
				logger.Info("heartbeat interval changed, resetting ticker",
					zap.Duration("old", currentInterval),
					zap.Duration("new", newInterval),
				)
				ticker.Reset(newInterval)
				currentInterval = newInterval
			}
		}
	}
}

// sendHeartbeat 发送心跳
func (m *Manager) sendHeartbeat() {
	// 采集 Agent 状态
	stat := m.collectAgentStat()

	// 采集主机信息
	hostInfo := m.collectHostInfo()

	// 采集插件状态
	pluginStats := m.collectPluginStats()

	// 采集资源指标
	resourceMetrics, err := m.resourceMon.Collect()
	if err != nil {
		m.logger.Warn("failed to collect resource metrics", zap.Error(err))
	}

	// 构建心跳记录
	record := &bridge.Record{
		DataType:  1000, // Agent 心跳数据类型
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"cpu_usage":  stat.CPUUsage,
				"mem_usage":  stat.MemUsage,
				"uptime":     stat.Uptime,
				"version":    m.cfg.GetVersion(),
				"product":    m.cfg.GetProduct(),
				"platform":   runtime.GOOS,
				"hostname":   hostInfo.Hostname,
				"os_family":  hostInfo.OSFamily,
				"os_version": hostInfo.OSVersion,
				"kernel":     hostInfo.Kernel,
				"arch":       hostInfo.Arch,
				// P5.3: kernel livepatch capability
				"livepatch_enabled":  boolToStr(hostInfo.LivepatchEnabled),
				"livepatch_provider": hostInfo.LivepatchProvider,
				"active_livepatches": strings.Join(hostInfo.ActiveLivepatches, ","),
			},
		},
	}

	// 添加资源指标到心跳记录
	// 字段名与 ClickHouse writer 保持一致：cpu_usage/mem_usage/disk_usage/net_in/net_out/load_*/disk_*_bytes
	if resourceMetrics != nil {
		record.Data.Fields["cpu_usage"] = fmt.Sprintf("%.2f", resourceMetrics.CPUUsage)
		record.Data.Fields["mem_usage"] = fmt.Sprintf("%.2f", resourceMetrics.MemUsage)
		record.Data.Fields["disk_usage"] = fmt.Sprintf("%.2f", resourceMetrics.DiskUsage)
		record.Data.Fields["disk_read_bytes"] = fmt.Sprintf("%d", resourceMetrics.DiskReadBytes)
		record.Data.Fields["disk_write_bytes"] = fmt.Sprintf("%d", resourceMetrics.DiskWriteBytes)
		record.Data.Fields["net_out"] = fmt.Sprintf("%d", resourceMetrics.NetBytesSent)
		record.Data.Fields["net_in"] = fmt.Sprintf("%d", resourceMetrics.NetBytesRecv)
		record.Data.Fields["agent_cpu_usage"] = fmt.Sprintf("%.2f", resourceMetrics.AgentCPUUsage)
		record.Data.Fields["agent_mem_rss"] = fmt.Sprintf("%d", resourceMetrics.AgentMemRSS)
		record.Data.Fields["agent_mem_percent"] = fmt.Sprintf("%.2f", resourceMetrics.AgentMemPercent)
	}

	// 采集硬件和系统信息
	hardwareInfo := m.collectHardwareInfo()
	if hardwareInfo != nil {
		if hardwareInfo.DeviceModel != "" {
			record.Data.Fields["device_model"] = hardwareInfo.DeviceModel
		}
		if hardwareInfo.Manufacturer != "" {
			record.Data.Fields["manufacturer"] = hardwareInfo.Manufacturer
		}
		if hardwareInfo.DeviceSerial != "" {
			record.Data.Fields["device_serial"] = hardwareInfo.DeviceSerial
		}
		if hardwareInfo.CPUInfo != "" {
			record.Data.Fields["cpu_info"] = hardwareInfo.CPUInfo
		}
		if hardwareInfo.MemorySize != "" {
			record.Data.Fields["memory_size"] = hardwareInfo.MemorySize
		}
		if hardwareInfo.SystemLoad != "" {
			record.Data.Fields["system_load"] = hardwareInfo.SystemLoad
			// 将 "1.0, 5.0, 15.0" 解析为独立字段，供 ClickHouse writer 使用
			if loads := strings.Split(hardwareInfo.SystemLoad, ", "); len(loads) >= 3 {
				record.Data.Fields["load_1"] = loads[0]
				record.Data.Fields["load_5"] = loads[1]
				record.Data.Fields["load_15"] = loads[2]
			}
		}
	}

	// 采集网络信息
	networkInfo := m.collectNetworkInfo()
	if networkInfo != nil {
		if networkInfo.DefaultGateway != "" {
			record.Data.Fields["default_gateway"] = networkInfo.DefaultGateway
		}
		if len(networkInfo.DNSServers) > 0 {
			record.Data.Fields["dns_servers"] = strings.Join(networkInfo.DNSServers, ",")
		}
		if networkInfo.NetworkMode != "" {
			record.Data.Fields["network_mode"] = networkInfo.NetworkMode
		}
	}

	// 采集系统启动时间
	systemBootTime := m.collectSystemBootTime()
	if systemBootTime != nil {
		record.Data.Fields["system_boot_time"] = systemBootTime.Format(time.RFC3339)
	}

	// 添加客户端启动时间
	record.Data.Fields["agent_start_time"] = m.startTime.Format(time.RFC3339)

	// 使用共享的运行时检测（全局单例，只检测一次）
	rtInfo := agentrt.Get()
	record.Data.Fields["runtime_type"] = string(rtInfo.Type)
	if rtInfo.IsContainer {
		record.Data.Fields["is_container"] = "true"
		if rtInfo.ContainerID != "" {
			record.Data.Fields["container_id"] = rtInfo.ContainerID
		}
		// K8s 特有字段
		if rtInfo.Type == agentrt.TypeK8s {
			if rtInfo.PodName != "" {
				record.Data.Fields["pod_name"] = rtInfo.PodName
			}
			if rtInfo.Namespace != "" {
				record.Data.Fields["pod_namespace"] = rtInfo.Namespace
			}
			if rtInfo.PodUID != "" {
				record.Data.Fields["pod_uid"] = rtInfo.PodUID
			}
		}
	}

	// 采集磁盘信息
	diskCtx, diskCancel := context.WithTimeout(context.Background(), 5*time.Second)
	diskInfoJSON := CollectDiskInfo(diskCtx, m.logger)
	diskCancel()
	if diskInfoJSON != "" {
		record.Data.Fields["disk_info"] = diskInfoJSON
		m.logger.Debug("disk info collected", zap.Int("length", len(diskInfoJSON)))
	}

	// 采集网卡信息
	netCtx, netCancel := context.WithTimeout(context.Background(), 5*time.Second)
	networkInterfacesJSON := CollectNetworkInterfaces(netCtx, m.logger)
	netCancel()
	if networkInterfacesJSON != "" {
		record.Data.Fields["network_interfaces"] = networkInterfacesJSON
		m.logger.Debug("network interfaces collected", zap.Int("length", len(networkInterfacesJSON)))
	}

	// 添加 EDR 引擎状态
	if m.edrEngine != nil {
		record.Data.Fields["edr_mode"] = m.edrEngine.GetEDRMode()
		record.Data.Fields["edr_hook_type"] = m.edrEngine.GetEDRHookType()
		caps := m.edrEngine.GetEDRCapabilities()
		if len(caps) > 0 {
			record.Data.Fields["edr_capabilities"] = strings.Join(caps, ",")
		}
		fwd, drop := m.edrEngine.GetEDRStats()
		record.Data.Fields["edr_events_fwd"] = fmt.Sprintf("%d", fwd)
		record.Data.Fields["edr_events_drop"] = fmt.Sprintf("%d", drop)
		record.Data.Fields["edr_rules_version"] = m.edrEngine.RulesVersion()
		record.Data.Fields["edr_rules_count"] = fmt.Sprintf("%d", m.edrEngine.RulesCount())
		record.Data.Fields["edr_rules_matched"] = fmt.Sprintf("%d", m.edrEngine.RulesMatched())
		record.Data.Fields["edr_ioc_version"] = m.edrEngine.IOCVersion()
		record.Data.Fields["edr_ioc_count"] = fmt.Sprintf("%d", m.edrEngine.IOCCount())
		record.Data.Fields["edr_ioc_matched"] = fmt.Sprintf("%d", m.edrEngine.IOCMatched())
		record.Data.Fields["edr_yara_available"] = fmt.Sprintf("%t", m.edrEngine.YARAAvailable())
		yaraScanned, yaraMatched := m.edrEngine.YARAStats()
		record.Data.Fields["edr_yara_scanned"] = fmt.Sprintf("%d", yaraScanned)
		record.Data.Fields["edr_yara_matched"] = fmt.Sprintf("%d", yaraMatched)
		if rt := m.edrEngine.ContainerRuntime(); rt != "" {
			record.Data.Fields["edr_container_runtime"] = rt
		}
	}

	// 添加业务线信息（从环境变量读取）
	businessLine := os.Getenv("MXCWPP_BUSINESS_LINE")
	if businessLine != "" {
		record.Data.Fields["business_line"] = businessLine
		m.logger.Debug("business line from environment", zap.String("business_line", businessLine))
	}

	// 添加插件状态到心跳记录（JSON 格式）
	if len(pluginStats) > 0 {
		pluginStatsJSON, err := json.Marshal(pluginStats)
		if err == nil {
			record.Data.Fields["plugin_stats"] = string(pluginStatsJSON)
		}
	}

	// 序列化记录
	recordData, err := proto.Marshal(record)
	if err != nil {
		m.logger.Error("failed to marshal heartbeat record", zap.Error(err))
		return
	}

	// 构建 PackagedData
	packagedData := &grpc.PackagedData{
		Records: []*grpc.EncodedRecord{
			{
				DataType:  1000,
				Timestamp: time.Now().UnixNano(),
				Data:      recordData,
			},
		},
		AgentId:      m.agentID,
		IntranetIpv4: hostInfo.IntranetIPv4,
		ExtranetIpv4: hostInfo.ExtranetIPv4,
		IntranetIpv6: hostInfo.IntranetIPv6,
		ExtranetIpv6: hostInfo.ExtranetIPv6,
		Hostname:     hostInfo.Hostname,
		Version:      m.cfg.GetVersion(),
		Product:      m.cfg.GetProduct(),
	}

	// 发送心跳
	if err := m.transport.SendHeartbeat(packagedData); err != nil {
		m.logger.Error("failed to send heartbeat", zap.Error(err))
		return
	}

	m.logger.Debug("heartbeat sent successfully",
		zap.String("agent_id", m.agentID),
		zap.String("hostname", hostInfo.Hostname),
		zap.Int("record_count", len(packagedData.Records)),
	)
}

// AgentStat 是 Agent 状态信息
type AgentStat struct {
	CPUUsage string
	MemUsage string
	Uptime   string
}

// HostInfo 是主机信息
type HostInfo struct {
	Hostname     string
	OSFamily     string
	OSVersion    string
	Kernel       string
	Arch         string
	IntranetIPv4 []string
	ExtranetIPv4 []string
	IntranetIPv6 []string
	ExtranetIPv6 []string

	// P5.3: kernel livepatch 能力（agent 启动时 detect 上报，UI 提示 kernel 漏洞是否可热补）
	LivepatchEnabled  bool
	LivepatchProvider string   // kpatch / canonical-livepatch / ksplice / kgraft / none
	ActiveLivepatches []string // 已加载 livepatch 模块名（/sys/kernel/livepatch/*）
}

// collectAgentStat 采集 Agent 状态
func (m *Manager) collectAgentStat() *AgentStat {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// 计算 CPU 使用率（简化实现）
	cpuUsage := "0%"
	// TODO: 实现真实的 CPU 使用率计算

	// 计算内存使用率
	memUsage := fmt.Sprintf("%.2f%%", float64(memStats.Alloc)/float64(memStats.Sys)*100)

	// 计算运行时间
	uptime := time.Since(m.startTime).String()

	return &AgentStat{
		CPUUsage: cpuUsage,
		MemUsage: memUsage,
		Uptime:   uptime,
	}
}

// collectHostInfo 采集主机信息
func (m *Manager) collectHostInfo() *HostInfo {
	hostInfo := &HostInfo{
		Arch:         runtime.GOARCH,
		IntranetIPv4: []string{},
		ExtranetIPv4: []string{},
		IntranetIPv6: []string{},
		ExtranetIPv6: []string{},
	}

	// 读取主机名
	if hostname, err := os.Hostname(); err == nil {
		hostInfo.Hostname = hostname
	} else {
		hostInfo.Hostname = "unknown"
		m.logger.Warn("failed to get hostname", zap.Error(err))
	}

	// 读取 OS 信息
	osFamily, osVersion := m.readOSRelease()
	hostInfo.OSFamily = osFamily
	hostInfo.OSVersion = osVersion

	// 读取内核信息
	hostInfo.Kernel = m.readKernelVersion()

	// 读取网络接口信息
	m.collectNetworkInterfaces(hostInfo)

	// P5.3: 检测 kernel livepatch 能力
	hostInfo.LivepatchEnabled, hostInfo.LivepatchProvider, hostInfo.ActiveLivepatches = m.detectKernelLivepatch()

	return hostInfo
}

// boolToStr 心跳字段全是 string，bool 转 "true"/"false"
func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// detectKernelLivepatch 检测主机是否启用 kernel livepatch。
//
// 检查顺序：
//  1. /sys/kernel/livepatch/ 下有目录 → 已有 livepatch 加载（最准）
//  2. rpm -q kpatch / kpatch-patch（RHEL/CentOS）
//  3. dpkg -l canonical-livepatch（Ubuntu Pro）
//  4. uname -v 含 "kpatch"
//
// 返回 provider 标识方便 UI 显示。
func (m *Manager) detectKernelLivepatch() (enabled bool, provider string, active []string) {
	// 1. /sys/kernel/livepatch — 已加载的活跃 livepatch（通用，最准）
	if entries, err := os.ReadDir("/sys/kernel/livepatch"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			// 读 enabled 文件，1=活跃
			if data, err := os.ReadFile("/sys/kernel/livepatch/" + name + "/enabled"); err == nil {
				if strings.TrimSpace(string(data)) == "1" {
					active = append(active, name)
				}
			} else {
				// 没 enabled 文件也认为是 livepatch 模块（兼容老内核）
				active = append(active, name)
			}
		}
		if len(active) > 0 {
			enabled = true
			provider = "kernel.livepatch"
		}
	}

	// 2. RHEL/CentOS kpatch
	if out, err := exec.Command("rpm", "-q", "kpatch").Output(); err == nil &&
		!strings.Contains(string(out), "not installed") {
		enabled = true
		if provider == "" {
			provider = "kpatch"
		}
	}

	// 3. Ubuntu Pro canonical-livepatch
	if _, err := os.Stat("/usr/bin/canonical-livepatch"); err == nil {
		enabled = true
		if provider == "" {
			provider = "canonical-livepatch"
		}
	}

	// 4. kernel build 含 kpatch 标识（兜底）
	if out, err := exec.Command("uname", "-v").Output(); err == nil {
		if strings.Contains(strings.ToLower(string(out)), "kpatch") {
			enabled = true
			if provider == "" {
				provider = "kpatch (kernel-builtin)"
			}
		}
	}

	if !enabled {
		provider = "none"
	}
	return
}

// readOSRelease 读取 /etc/os-release 文件获取 OS 信息
func (m *Manager) readOSRelease() (osFamily, osVersion string) {
	// 尝试读取 /etc/os-release（systemd 标准）
	file, err := os.Open("/etc/os-release")
	if err != nil {
		// 尝试读取 /etc/redhat-release（RHEL/CentOS 旧版本）
		if redhatInfo := m.readRedhatRelease(); redhatInfo != "" {
			return m.parseRedhatRelease(redhatInfo)
		}
		m.logger.Warn("failed to open /etc/os-release", zap.Error(err))
		return "unknown", "unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	osFamily = "unknown"
	osVersion = "unknown"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 KEY="VALUE" 格式
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)

		switch key {
		case "ID":
			// ID 字段：rocky, centos, debian, ubuntu 等
			osFamily = value
		case "VERSION_ID":
			// VERSION_ID 字段：版本号
			osVersion = value
		case "ID_LIKE":
			// ID_LIKE 字段：如果 ID 不在我们支持的列表中，使用 ID_LIKE
			if osFamily == "unknown" {
				// ID_LIKE 可能是 "rhel fedora" 或 "debian"
				if strings.Contains(value, "rhel") || strings.Contains(value, "fedora") {
					osFamily = "rhel"
				} else if strings.Contains(value, "debian") {
					osFamily = "debian"
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		m.logger.Warn("failed to read /etc/os-release", zap.Error(err))
	}

	// 规范化 OS Family（统一命名）
	osFamily = m.normalizeOSFamily(osFamily)

	return osFamily, osVersion
}

// readRedhatRelease 读取 /etc/redhat-release 文件（RHEL/CentOS 旧版本）
func (m *Manager) readRedhatRelease() string {
	data, err := os.ReadFile("/etc/redhat-release")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parseRedhatRelease 解析 /etc/redhat-release 内容
func (m *Manager) parseRedhatRelease(content string) (osFamily, osVersion string) {
	content = strings.ToLower(content)

	// 识别发行版
	if strings.Contains(content, "rocky") {
		osFamily = "rocky"
	} else if strings.Contains(content, "centos") {
		osFamily = "centos"
	} else if strings.Contains(content, "oracle") {
		osFamily = "oracle"
	} else if strings.Contains(content, "red hat") {
		osFamily = "rhel"
	} else {
		osFamily = "unknown"
	}

	// 提取版本号（简单正则匹配）
	// 例如：Rocky Linux release 9.3 (Blue Onyx)
	parts := strings.Fields(content)
	for i, part := range parts {
		if part == "release" && i+1 < len(parts) {
			version := parts[i+1]
			// 移除可能的括号内容
			if idx := strings.Index(version, "("); idx != -1 {
				version = version[:idx]
			}
			osVersion = strings.TrimSpace(version)
			break
		}
	}

	return osFamily, osVersion
}

// normalizeOSFamily 规范化 OS Family 名称
func (m *Manager) normalizeOSFamily(family string) string {
	family = strings.ToLower(family)

	// 映射常见变体
	switch family {
	case "rocky", "rocky linux":
		return "rocky"
	case "centos", "centos linux":
		return "centos"
	case "rhel", "redhat", "red hat enterprise linux":
		return "rhel"
	case "oracle", "oracle linux":
		return "oracle"
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	default:
		return family
	}
}

// readKernelVersion 读取 /proc/version 获取内核版本
func (m *Manager) readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		m.logger.Warn("failed to read /proc/version", zap.Error(err))
		return "unknown"
	}

	// /proc/version 格式：Linux version 5.14.0-284.30.1.el9_2.x86_64 (mockbuild@...) ...
	version := strings.TrimSpace(string(data))

	// 提取内核版本号（简化处理，取前100个字符）
	if len(version) > 100 {
		version = version[:100]
	}

	return version
}

// collectNetworkInterfaces 采集网络接口信息
func (m *Manager) collectNetworkInterfaces(hostInfo *HostInfo) {
	interfaces, err := net.Interfaces()
	if err != nil {
		m.logger.Warn("failed to get network interfaces", zap.Error(err))
		return
	}

	for _, iface := range interfaces {
		// 跳过回环接口和未启用的接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			// 跳过回环地址
			if ip.IsLoopback() {
				continue
			}

			// 判断是否为内网地址
			isPrivate := ip.IsPrivate() || ip.IsLinkLocalUnicast()

			if ip.To4() != nil {
				// IPv4 地址
				ipStr := ip.String()
				if isPrivate {
					hostInfo.IntranetIPv4 = append(hostInfo.IntranetIPv4, ipStr)
				} else {
					hostInfo.ExtranetIPv4 = append(hostInfo.ExtranetIPv4, ipStr)
				}
			} else {
				// IPv6 地址
				ipStr := ip.String()
				if isPrivate || ip.IsLinkLocalUnicast() {
					hostInfo.IntranetIPv6 = append(hostInfo.IntranetIPv6, ipStr)
				} else {
					hostInfo.ExtranetIPv6 = append(hostInfo.ExtranetIPv6, ipStr)
				}
			}
		}
	}

	// 如果没有找到内网 IPv4，尝试使用 hostname -I 命令（某些系统）
	if len(hostInfo.IntranetIPv4) == 0 {
		if ip := m.getIPFromHostname(); ip != "" {
			hostInfo.IntranetIPv4 = append(hostInfo.IntranetIPv4, ip)
		}
	}
}

// getIPFromHostname 使用 hostname -I 命令获取 IP（备用方法）
func (m *Manager) getIPFromHostname() string {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// hostname -I 输出格式：192.168.1.1 10.0.0.1 ...
	ips := strings.Fields(string(output))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ipStr
		}
	}

	return ""
}

// collectPluginStats 采集插件状态
func (m *Manager) collectPluginStats() map[string]interface{} {
	if m.pluginMgr == nil {
		return nil
	}
	return m.pluginMgr.GetAllPluginStats()
}

// HardwareInfo 硬件信息
type HardwareInfo struct {
	DeviceModel  string // 设备型号
	Manufacturer string // 制造商
	DeviceSerial string // 设备序列号
	CPUInfo      string // CPU信息（型号、核心数、频率）
	MemorySize   string // 内存大小
	SystemLoad   string // 系统负载
}

// NetworkInfo 网络信息
type NetworkInfo struct {
	DefaultGateway string   // 默认网关
	DNSServers     []string // DNS服务器列表
	NetworkMode    string   // 网络模式
}

// collectHardwareInfo 采集硬件信息
func (m *Manager) collectHardwareInfo() *HardwareInfo {
	info := &HardwareInfo{}

	// 优先从 DMI 读取设备型号（/sys/class/dmi/id/product_name）
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		deviceModel := strings.TrimSpace(string(data))
		// 过滤掉无效值（如 "Not Specified", "To be filled by O.E.M." 等）
		if deviceModel != "" && !strings.Contains(strings.ToLower(deviceModel), "not specified") &&
			!strings.Contains(strings.ToLower(deviceModel), "to be filled") &&
			!strings.Contains(strings.ToLower(deviceModel), "o.e.m.") {
			info.DeviceModel = deviceModel
		}
	}

	// 如果 DMI 未获取到，尝试使用 dmidecode 命令
	if info.DeviceModel == "" {
		if model := m.readDMIByCommand("product-name"); model != "" {
			info.DeviceModel = model
		}
	}

	// 优先从 DMI 读取制造商（/sys/class/dmi/id/sys_vendor）
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		manufacturer := strings.TrimSpace(string(data))
		// 过滤掉无效值
		if manufacturer != "" && !strings.Contains(strings.ToLower(manufacturer), "not specified") &&
			!strings.Contains(strings.ToLower(manufacturer), "to be filled") &&
			!strings.Contains(strings.ToLower(manufacturer), "o.e.m.") {
			info.Manufacturer = manufacturer
		}
	}

	// 如果 DMI 未获取到，尝试使用 dmidecode 命令
	if info.Manufacturer == "" {
		if vendor := m.readDMIByCommand("system-manufacturer"); vendor != "" {
			info.Manufacturer = vendor
		}
	}

	// 优先从 DMI 读取设备序列号（/sys/class/dmi/id/product_serial）
	if data, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		deviceSerial := strings.TrimSpace(string(data))
		// 过滤掉无效值
		if deviceSerial != "" && !strings.Contains(strings.ToLower(deviceSerial), "not specified") &&
			!strings.Contains(strings.ToLower(deviceSerial), "to be filled") &&
			!strings.Contains(strings.ToLower(deviceSerial), "o.e.m.") &&
			deviceSerial != "Default string" {
			info.DeviceSerial = deviceSerial
		}
	}

	// 如果 DMI 未获取到，尝试使用 dmidecode 命令
	if info.DeviceSerial == "" {
		if serial := m.readDMIByCommand("product-serial"); serial != "" {
			info.DeviceSerial = serial
		}
	}

	// 读取CPU信息（/proc/cpuinfo）
	info.CPUInfo = m.readCPUInfo()

	// 读取内存大小（/proc/meminfo）
	info.MemorySize = m.readMemorySize()

	// 读取系统负载（/proc/loadavg）
	info.SystemLoad = m.readSystemLoad()

	return info
}

// readDMIByCommand 使用 dmidecode 命令读取 DMI 信息（降级方案）
func (m *Manager) readDMIByCommand(key string) string {
	// 构建 dmidecode 命令参数
	var arg string
	switch key {
	case "product-name":
		arg = "-s system-product-name"
	case "system-manufacturer":
		arg = "-s system-manufacturer"
	case "product-serial":
		arg = "-s system-serial-number"
	default:
		return ""
	}

	// 执行 dmidecode 命令
	cmd := exec.Command("dmidecode", arg)
	output, err := cmd.Output()
	if err != nil {
		m.logger.Debug("dmidecode command failed", zap.String("key", key), zap.Error(err))
		return ""
	}

	result := strings.TrimSpace(string(output))
	// 过滤掉无效值
	if result != "" && !strings.Contains(strings.ToLower(result), "not specified") &&
		!strings.Contains(strings.ToLower(result), "to be filled") &&
		!strings.Contains(strings.ToLower(result), "o.e.m.") &&
		result != "Default string" {
		return result
	}

	return ""
}

// readCPUInfo 读取CPU信息
func (m *Manager) readCPUInfo() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		m.logger.Debug("failed to read /proc/cpuinfo", zap.Error(err))
		return ""
	}

	lines := strings.Split(string(data), "\n")
	var modelName string
	var cpuCores int
	var cpuMHz string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				modelName = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "cpu MHz") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpuMHz = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "processor") {
			cpuCores++
		}
	}

	// 如果没有找到processor字段，尝试统计物理核心数
	if cpuCores == 0 {
		// 统计不同的physical id
		physicalIDs := make(map[string]bool)
		for _, line := range lines {
			if strings.HasPrefix(line, "physical id") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					physicalIDs[strings.TrimSpace(parts[1])] = true
				}
			}
		}
		if len(physicalIDs) > 0 {
			// 统计每个物理CPU的核心数
			cpuCores = len(physicalIDs)
		} else {
			// 如果还是找不到，使用processor数量
			cpuCores = strings.Count(string(data), "processor")
		}
	}

	// 构建CPU信息字符串
	if modelName != "" {
		result := modelName
		if cpuCores > 0 {
			result += fmt.Sprintf(" (%d cores)", cpuCores)
		}
		if cpuMHz != "" {
			result += fmt.Sprintf(" @ %s MHz", cpuMHz)
		}
		return result
	}

	return ""
}

// readMemorySize 读取内存大小
func (m *Manager) readMemorySize() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		m.logger.Debug("failed to read /proc/meminfo", zap.Error(err))
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// MemTotal: 值 kB
				value, err := strconv.ParseInt(parts[1], 10, 64)
				if err == nil {
					// 转换为GB
					gb := float64(value) / 1024 / 1024
					if gb < 1 {
						// 小于1GB，显示MB
						return fmt.Sprintf("%.0f MB", float64(value)/1024)
					}
					return fmt.Sprintf("%.2f GB", gb)
				}
			}
		}
	}

	return ""
}

// readSystemLoad 读取系统负载
func (m *Manager) readSystemLoad() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		m.logger.Debug("failed to read /proc/loadavg", zap.Error(err))
		return ""
	}

	// /proc/loadavg 格式：1min 5min 15min
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
	}

	return ""
}

// collectNetworkInfo 采集网络信息
func (m *Manager) collectNetworkInfo() *NetworkInfo {
	info := &NetworkInfo{}

	// 读取默认网关（通过 ip route 命令）
	info.DefaultGateway = m.readDefaultGateway()

	// 读取DNS服务器（/etc/resolv.conf）
	info.DNSServers = m.readDNSServers()

	// 判断网络模式（简化实现，基于是否有多个网络接口）
	info.NetworkMode = m.detectNetworkMode()

	return info
}

// readDefaultGateway 读取默认网关
func (m *Manager) readDefaultGateway() string {
	// 尝试使用 ip route 命令
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "default via") {
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "via" && i+1 < len(fields) {
						return fields[i+1]
					}
				}
			}
		}
	}

	// 备用方法：读取 /proc/net/route
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "00000000" {
				// 找到默认路由，提取网关
				if len(fields) >= 3 {
					gatewayHex := fields[2]
					// 将十六进制转换为IP地址
					if len(gatewayHex) == 8 {
						gatewayIP := m.hexToIP(gatewayHex)
						if gatewayIP != "" {
							return gatewayIP
						}
					}
				}
			}
		}
	}

	return ""
}

// hexToIP 将十六进制字符串转换为IP地址
func (m *Manager) hexToIP(hexStr string) string {
	// 格式：0101A8C0 -> 192.168.1.1（小端序）
	if len(hexStr) != 8 {
		return ""
	}

	var parts []string
	for i := 0; i < 8; i += 2 {
		hexByte := hexStr[i : i+2]
		val, err := strconv.ParseUint(hexByte, 16, 8)
		if err != nil {
			return ""
		}
		parts = append([]string{strconv.FormatUint(val, 10)}, parts...)
	}

	return strings.Join(parts, ".")
}

// readDNSServers 读取DNS服务器列表
func (m *Manager) readDNSServers() []string {
	var servers []string

	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		m.logger.Debug("failed to read /etc/resolv.conf", zap.Error(err))
		return servers
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				servers = append(servers, fields[1])
			}
		}
	}

	return servers
}

// detectNetworkMode 检测网络模式
func (m *Manager) detectNetworkMode() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	activeCount := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			activeCount++
		}
	}

	if activeCount == 0 {
		return "none"
	} else if activeCount == 1 {
		return "single"
	} else {
		return "multi"
	}
}

// collectSystemBootTime 采集系统启动时间
func (m *Manager) collectSystemBootTime() *time.Time {
	// 方法1：读取 /proc/stat 中的 btime（系统启动时间戳，秒）
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if timestamp, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						bootTime := time.Unix(timestamp, 0)
						return &bootTime
					}
				}
			}
		}
	}

	// 方法2：使用 uptime 命令计算（备用方法）
	// 通过读取 /proc/uptime 计算启动时间
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			if uptimeSeconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
				bootTime := time.Now().Add(-time.Duration(uptimeSeconds) * time.Second)
				return &bootTime
			}
		}
	}

	m.logger.Debug("failed to collect system boot time")
	return nil
}
