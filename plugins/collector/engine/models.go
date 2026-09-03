// Package engine 提供采集引擎的核心功能
package engine

import (
	"encoding/json"
	"time"
)

// Asset 是资产数据的基础结构
type Asset struct {
	HostID      string    `json:"host_id"`
	CollectedAt time.Time `json:"collected_at"`
}

// ProcessAsset 是进程资产数据
type ProcessAsset struct {
	Asset
	PID         string `json:"pid"`
	PPID        string `json:"ppid"`
	Cmdline     string `json:"cmdline"`
	Exe         string `json:"exe"`
	ExeHash     string `json:"exe_hash,omitempty"` // MD5 哈希值
	ContainerID string `json:"container_id,omitempty"`
	UID         string `json:"uid"`
	GID         string `json:"gid"`
	Username    string `json:"username,omitempty"`
	Groupname   string `json:"groupname,omitempty"`
}

// PortAsset 是端口资产数据
type PortAsset struct {
	Asset
	Protocol    string `json:"protocol"` // tcp/udp
	Port        int    `json:"port"`     // 端口号
	State       string `json:"state"`    // LISTEN/ESTABLISHED 等
	PID         string `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

// UserAsset 是账户资产数据
type UserAsset struct {
	Asset
	Username    string `json:"username"`
	UID         string `json:"uid"`
	GID         string `json:"gid"`
	Groupname   string `json:"groupname,omitempty"`
	HomeDir     string `json:"home_dir"`
	Shell       string `json:"shell"`
	Comment     string `json:"comment,omitempty"`
	HasPassword bool   `json:"has_password"` // 是否有密码（基于 shadow 文件）
}

// SoftwareAsset 是软件包资产数据
type SoftwareAsset struct {
	Asset
	Name         string `json:"name"`                   // 软件包名称
	Version      string `json:"version"`                // 版本号
	Epoch        string `json:"epoch,omitempty"`        // RPM EPOCH 字段（不存在则空）。NEVRA 精确比较核心
	Release      string `json:"release,omitempty"`      // RPM RELEASE 字段（如 "284.11.1.el9_2"）。NEVRA 精确比较核心
	Architecture string `json:"architecture"`           // 架构（x86_64、aarch64 等）
	PackageType  string `json:"package_type"`           // 包类型（rpm、deb、pip、npm、jar、go-binary、go-module 等）
	Vendor       string `json:"vendor,omitempty"`       // 供应商
	InstallTime  string `json:"install_time,omitempty"` // 安装时间
	PURL         string `json:"purl,omitempty"`         // Package URL (用于漏洞匹配)
	// Scope 控制漏洞匹配维度，CWPP 防误报核心字段：
	//   system   = 主机/容器上独立运行的服务/二进制本体（参与 CPE daemon + PURL 匹配）
	//   embedded = 静态链接进宿主 binary 的依赖库（仅参与 PURL 匹配，不参与 CPE）
	//   container = 容器内的包（独立命名空间，由 container_sbom 出）
	// 缺省按 system 处理（向后兼容旧版 collector）。
	Scope string `json:"scope,omitempty"`
	// SourceHandler 标识哪个 handler 采集的（rpm/dpkg/binary_probe/jar/go_buildinfo/python/node/container_sbom）。
	// 用于追溯、误报排查与数据修订。
	SourceHandler string `json:"source_handler,omitempty"`
	// HostBinaryPath 仅对 scope=embedded 有效：宿主 binary 路径
	// 例：mxcwpp-agent 内嵌 github.com/docker/docker → HostBinaryPath = /usr/local/bin/mxcwpp-agent
	// 用于排查"为什么这个 module 出现在该主机上"。
	HostBinaryPath string `json:"host_binary_path,omitempty"`
}

// ContainerAsset 是容器资产数据
type ContainerAsset struct {
	Asset
	ContainerID   string `json:"container_id"`         // 容器 ID
	ContainerName string `json:"container_name"`       // 容器名称
	Image         string `json:"image"`                // 镜像名称
	ImageID       string `json:"image_id"`             // 镜像 ID
	Runtime       string `json:"runtime"`              // 运行时（docker、containerd）
	Status        string `json:"status"`               // 状态（running、stopped 等）
	CreatedAt     string `json:"created_at,omitempty"` // 创建时间
}

// AppAsset 是应用资产数据
type AppAsset struct {
	Asset
	AppType    string `json:"app_type"`              // 应用类型（mysql、redis、nginx、kafka 等）
	AppName    string `json:"app_name"`              // 应用名称
	Version    string `json:"version,omitempty"`     // 版本号
	Port       int    `json:"port,omitempty"`        // 端口号
	ProcessID  string `json:"process_id,omitempty"`  // 进程 ID
	ConfigPath string `json:"config_path,omitempty"` // 配置文件路径
	DataPath   string `json:"data_path,omitempty"`   // 数据目录路径
}

// NetInterfaceAsset 是网络接口资产数据
type NetInterfaceAsset struct {
	Asset
	InterfaceName string   `json:"interface_name"`          // 接口名称（eth0、ens33 等）
	MACAddress    string   `json:"mac_address"`             // MAC 地址
	IPv4Addresses []string `json:"ipv4_addresses"`          // IPv4 地址列表
	IPv6Addresses []string `json:"ipv6_addresses"`          // IPv6 地址列表
	MTU           int      `json:"mtu"`                     // MTU
	State         string   `json:"state"`                   // 状态（up、down）
	BytesRecv     uint64   `json:"bytes_recv,omitempty"`    // 累计接收字节数（/proc/net/dev）
	BytesSent     uint64   `json:"bytes_sent,omitempty"`    // 累计发送字节数
	PacketsDrop   uint64   `json:"packets_drop,omitempty"`  // 接收丢包数
	PacketsError  uint64   `json:"packets_error,omitempty"` // 接收错误数
}

// VolumeAsset 是磁盘资产数据
type VolumeAsset struct {
	Asset
	Device        string  `json:"device"`         // 设备名称（/dev/sda1）
	MountPoint    string  `json:"mount_point"`    // 挂载点（/、/home 等）
	FileSystem    string  `json:"file_system"`    // 文件系统类型（ext4、xfs 等）
	TotalSize     int64   `json:"total_size"`     // 总大小（字节）
	UsedSize      int64   `json:"used_size"`      // 已用大小（字节）
	AvailableSize int64   `json:"available_size"` // 可用大小（字节）
	UsagePercent  float64 `json:"usage_percent"`  // 使用率（百分比）
}

// KmodAsset 是内核模块资产数据
type KmodAsset struct {
	Asset
	ModuleName string `json:"module_name"` // 模块名称
	Size       int64  `json:"size"`        // 模块大小（字节）
	UsedBy     int    `json:"used_by"`     // 引用计数
	State      string `json:"state"`       // 状态（Live、Loading、Unloading）
}

// ServiceAsset 是系统服务资产数据
type ServiceAsset struct {
	Asset
	ServiceName string `json:"service_name"`          // 服务名称
	ServiceType string `json:"service_type"`          // 服务类型（systemd、sysv）
	Status      string `json:"status"`                // 状态（active、inactive、failed 等）
	Enabled     bool   `json:"enabled"`               // 是否开机自启
	Description string `json:"description,omitempty"` // 服务描述
}

// CronAsset 是定时任务资产数据
type CronAsset struct {
	Asset
	User     string `json:"user"`      // 用户（root、username）
	Schedule string `json:"schedule"`  // 调度表达式（* * * * *）
	Command  string `json:"command"`   // 执行的命令
	CronType string `json:"cron_type"` // 类型（crontab、systemd-timer）
	Enabled  bool   `json:"enabled"`   // 是否启用
}

// SerializeAssets 序列化资产数据为 JSON
func SerializeAssets(assets interface{}) ([]byte, error) {
	return json.Marshal(assets)
}

// GetDataType 根据采集类型返回对应的 data_type
func GetDataType(collectType string) int32 {
	switch collectType {
	case "process":
		return 5050
	case "port":
		return 5051
	case "user":
		return 5052
	case "software", "binary_probe", "python_packages", "node_packages", "jar_scanner", "go_buildinfo", "container_sbom":
		// 全部 SBOM 类 handler 复用 5053 (软件资产)。
		// server 端按 source_file / package_type / purl 区分来源，避免 DataType 爆炸。
		return 5053
	case "container":
		return 5054
	case "app":
		return 5055
	case "network":
		return 5056
	case "volume":
		return 5057
	case "kmod":
		return 5058
	case "service":
		return 5059
	case "cron":
		return 5060
	default:
		return 0
	}
}
