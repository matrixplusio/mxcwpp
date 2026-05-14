// Package engine 提供 Tetragon eBPF 事件采集引擎的核心功能
package engine

import "time"

// DataType 常量 - Sensor 事件上报类型
const (
	DataTypeProcessEvent int32 = 3000 // 进程事件（上行）
	DataTypeFileEvent    int32 = 3001 // 文件事件（上行）
	DataTypeNetworkEvent int32 = 3002 // 网络事件（上行）
)

// TetragonEvent 表示从 Tetragon 接收到的一个事件
type TetragonEvent struct {
	EventType string       // process_exec, process_exit, file_open, tcp_connect, tcp_close
	Timestamp time.Time    // 事件时间戳
	Process   *ProcessInfo // 进程信息（所有事件都包含）
	File      *FileInfo    // 文件信息（仅文件事件）
	Network   *NetworkInfo // 网络信息（仅网络事件）
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID       uint32 // 进程 ID
	PPID      uint32 // 父进程 ID
	Exe       string // 可执行文件路径
	Cmdline   string // 命令行参数
	ParentExe string // 父进程可执行文件路径
	UID       uint32 // 用户 ID
	GID       uint32 // 组 ID
}

// FileInfo 文件信息
type FileInfo struct {
	Path  string // 文件路径
	Flags string // 打开标志
}

// NetworkInfo 网络信息
type NetworkInfo struct {
	RemoteAddr string // 远程地址
	RemotePort uint32 // 远程端口
	LocalAddr  string // 本地地址
	LocalPort  uint32 // 本地端口（入站连接时为被访问端口）
	Protocol   string // 协议（tcp, udp）
}

// EventTypeToDataType 将 Tetragon 事件类型映射到 DataType
func EventTypeToDataType(eventType string) int32 {
	switch eventType {
	case "process_exec", "process_exit":
		return DataTypeProcessEvent
	case "file_open":
		return DataTypeFileEvent
	case "tcp_connect", "tcp_close", "tcp_accept", "icmp_recv":
		return DataTypeNetworkEvent
	default:
		return DataTypeProcessEvent
	}
}
