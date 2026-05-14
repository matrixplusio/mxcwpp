// Package model 提供数据库模型定义
package model

import (
	"database/sql/driver"
	"encoding/json"
)

// HostStatus 主机状态
type HostStatus string

const (
	HostStatusOnline  HostStatus = "online"
	HostStatusOffline HostStatus = "offline"
)

// RuntimeType 运行时类型
type RuntimeType string

const (
	RuntimeTypeVM     RuntimeType = "vm"     // 虚拟机或物理机
	RuntimeTypeDocker RuntimeType = "docker" // Docker 容器
	RuntimeTypeK8s    RuntimeType = "k8s"    // Kubernetes Pod
)

// IsValidRuntimeType 检查运行时类型是否有效
func IsValidRuntimeType(rt string) bool {
	switch RuntimeType(rt) {
	case RuntimeTypeVM, RuntimeTypeDocker, RuntimeTypeK8s:
		return true
	default:
		return false
	}
}

// StringArray 字符串数组类型，用于 JSON 字段
type StringArray []string

// Value 实现 driver.Valuer 接口
func (a StringArray) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan 实现 sql.Scanner 接口
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = StringArray{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, a)
}

// Host 主机信息模型
type Host struct {
	HostID        string      `gorm:"primaryKey;column:host_id;type:varchar(64);not null" json:"host_id"`
	Hostname      string      `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	OSFamily      string      `gorm:"column:os_family;type:varchar(50)" json:"os_family"`
	OSVersion     string      `gorm:"column:os_version;type:varchar(50)" json:"os_version"`
	KernelVersion string      `gorm:"column:kernel_version;type:varchar(100)" json:"kernel_version"`
	Arch          string      `gorm:"column:arch;type:varchar(20)" json:"arch"`
	IPv4          StringArray `gorm:"column:ipv4;type:json" json:"ipv4"`
	IPv6          StringArray `gorm:"column:ipv6;type:json" json:"ipv6"`
	PublicIPv4    StringArray `gorm:"column:public_ipv4;type:json" json:"public_ipv4"` // 公网IPv4地址
	PublicIPv6    StringArray `gorm:"column:public_ipv6;type:json" json:"public_ipv6"` // 公网IPv6地址
	Status        HostStatus  `gorm:"column:status;type:varchar(20);default:'offline'" json:"status"`
	LastHeartbeat *LocalTime  `gorm:"column:last_heartbeat;type:timestamp" json:"last_heartbeat"`
	// 硬件信息
	DeviceModel  string `gorm:"column:device_model;type:varchar(255)" json:"device_model"`
	Manufacturer string `gorm:"column:manufacturer;type:varchar(255)" json:"manufacturer"`
	DeviceSerial string `gorm:"column:device_serial;type:varchar(255)" json:"device_serial"`
	DeviceID     string `gorm:"column:device_id;type:varchar(64)" json:"device_id"` // 设备ID（可能与host_id相同）
	CPUInfo      string `gorm:"column:cpu_info;type:varchar(500)" json:"cpu_info"`
	MemorySize   string `gorm:"column:memory_size;type:varchar(50)" json:"memory_size"`
	SystemLoad   string `gorm:"column:system_load;type:varchar(100)" json:"system_load"`
	// 网络信息
	DefaultGateway string      `gorm:"column:default_gateway;type:varchar(50)" json:"default_gateway"`
	DNSServers     StringArray `gorm:"column:dns_servers;type:json" json:"dns_servers"`
	NetworkMode    string      `gorm:"column:network_mode;type:varchar(50)" json:"network_mode"`
	// 磁盘信息（JSON 格式，存储磁盘列表）
	DiskInfo string `gorm:"column:disk_info;type:text" json:"disk_info"` // JSON 数组，包含磁盘设备、挂载点、文件系统、大小等信息
	// 网卡信息（JSON 格式，存储网卡列表）
	NetworkInterfaces string `gorm:"column:network_interfaces;type:text" json:"network_interfaces"` // JSON 数组，包含网卡名称、MAC地址、IP地址、MTU、状态等信息
	// 业务信息
	BusinessLine string `gorm:"column:business_line;type:varchar(100)" json:"business_line"` // 业务线
	// 时间信息
	SystemBootTime *LocalTime `gorm:"column:system_boot_time;type:timestamp" json:"system_boot_time"` // 系统启动时间
	AgentStartTime *LocalTime `gorm:"column:agent_start_time;type:timestamp" json:"agent_start_time"` // 客户端启动时间
	LastActiveTime *LocalTime `gorm:"column:last_active_time;type:timestamp" json:"last_active_time"` // 最近活跃时间
	// 运行时环境
	RuntimeType RuntimeType `gorm:"column:runtime_type;type:varchar(20);default:'vm'" json:"runtime_type"` // 运行时类型：vm/docker/k8s
	IsContainer bool        `gorm:"column:is_container;type:tinyint(1);default:0" json:"is_container"`     // 是否为容器环境
	ContainerID string      `gorm:"column:container_id;type:varchar(64)" json:"container_id"`              // 容器ID（如果是在容器中运行）
	// K8s 相关字段
	PodName      string `gorm:"column:pod_name;type:varchar(255)" json:"pod_name"`           // Pod 名称（K8s 环境）
	PodNamespace string `gorm:"column:pod_namespace;type:varchar(255)" json:"pod_namespace"` // 命名空间（K8s 环境）
	PodUID       string `gorm:"column:pod_uid;type:varchar(64)" json:"pod_uid"`              // Pod UID（K8s 环境）
	// Agent 版本信息
	AgentVersion string `gorm:"column:agent_version;type:varchar(32)" json:"agent_version"` // Agent 当前版本号
	// 标签
	Tags      StringArray `gorm:"column:tags;type:json" json:"tags"`
	CreatedAt LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime   `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (Host) TableName() string {
	return "hosts"
}
