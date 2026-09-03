//go:build windows

// etw_windows.go — Windows ETW (Event Tracing for Windows) collector 骨架 (C7).
//
// Windows EDR 等价 Linux eBPF 的能力栈:
//   - ETW: Sysmon / Microsoft-Windows-Kernel-Process / Network / FileMonitor
//   - WMI: 实时 query (Win32_Process / Win32_ProcessStartTrace)
//   - WFP: Windows Filtering Platform 网络 hook
//   - 驱动 (Sprint 5+): minifilter 文件级 + NDIS 网络
//
// 本 PR 给 ETW collector + WMI sink 骨架, 真实接入用 golang.org/x/sys/windows
// + 第三方 etw lib (e.g. github.com/0xrawsec/golang-etw).
package collector

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// EventKind Windows 端事件类型.
type WindowsEventKind string

const (
	WinEventProcessStart    WindowsEventKind = "process_start"
	WinEventProcessEnd      WindowsEventKind = "process_end"
	WinEventNetworkConnect  WindowsEventKind = "network_connect"
	WinEventFileWrite       WindowsEventKind = "file_write"
	WinEventRegistryWrite   WindowsEventKind = "registry_write"
	WinEventImageLoad       WindowsEventKind = "image_load"
	WinEventDriverLoad      WindowsEventKind = "driver_load"
	WinEventThreadCreate    WindowsEventKind = "thread_create"
	WinEventNamedPipeCreate WindowsEventKind = "namedpipe_create"
)

// WindowsEvent 统一事件结构.
type WindowsEvent struct {
	Kind        WindowsEventKind
	PID         uint32
	ParentPID   uint32
	Image       string
	CommandLine string
	User        string
	TimeStamp   time.Time

	// 网络
	DstIP    string
	DstPort  uint16
	SrcIP    string
	SrcPort  uint16
	Protocol string

	// 文件
	FilePath string

	// 注册表
	RegistryKey   string
	RegistryValue string

	// 镜像/驱动
	ImageHash string

	Raw map[string]any
}

// ETWCollector ETW session 包装.
type ETWCollector struct {
	logger *zap.Logger
	events chan WindowsEvent
	stopCh chan struct{}
	cfg    ETWConfig
}

// ETWConfig 配置.
type ETWConfig struct {
	SessionName       string   // ETW session 名 (默认 mxcwpp-etw)
	Providers         []string // GUID 列表 / 名称别名 (Sysmon / Kernel-Process / Kernel-Network)
	BufferSize        int      // 单 buffer KB (默认 64)
	MinBuffers        int      // (默认 4)
	MaxBuffers        int      // (默认 16)
	IncludeStackTrace bool
}

// DefaultETWConfig 默认值.
func DefaultETWConfig() ETWConfig {
	return ETWConfig{
		SessionName: "mxcwpp-etw",
		Providers: []string{
			"Microsoft-Windows-Kernel-Process",
			"Microsoft-Windows-Kernel-Network",
			"Microsoft-Windows-Kernel-File",
			"Microsoft-Windows-Kernel-Registry",
			// Sysmon (若装)
			"Microsoft-Windows-Sysmon",
		},
		BufferSize:        64,
		MinBuffers:        4,
		MaxBuffers:        16,
		IncludeStackTrace: false,
	}
}

// NewETWCollector 构造.
func NewETWCollector(cfg ETWConfig, logger *zap.Logger) *ETWCollector {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ETWCollector{
		logger: logger,
		cfg:    cfg,
		events: make(chan WindowsEvent, 1024),
		stopCh: make(chan struct{}),
	}
}

// Events 订阅.
func (c *ETWCollector) Events() <-chan WindowsEvent { return c.events }

// Start 启 ETW session.
//
// 当前 stub: 仅记录意图, 真实 ETW session 接入待引入 golang-etw 依赖 (Sprint 5+).
func (c *ETWCollector) Start(ctx context.Context) error {
	c.logger.Info("ETW collector started (stub)",
		zap.String("session", c.cfg.SessionName),
		zap.Int("providers", len(c.cfg.Providers)))
	// TODO(C7-followup): etw.NewRealTimeSession + EnableProvider + ParseEvent loop
	<-ctx.Done()
	close(c.stopCh)
	return nil
}

// Stop 关 session.
func (c *ETWCollector) Stop() error {
	select {
	case <-c.stopCh:
		return nil
	default:
		close(c.stopCh)
		return nil
	}
}

// WMIQuery 单次同步 WMI 查询.
//
// 真实接入需 github.com/StackExchange/wmi.
func WMIQuery(query string) ([]map[string]any, error) {
	return nil, errors.New("wmi: not yet wired (Sprint 5+)")
}

// EnumProcessesWMI 等价 Linux /proc 枚举.
func EnumProcessesWMI() ([]WindowsEvent, error) {
	return nil, errors.New("wmi: not yet wired (Sprint 5+)")
}
