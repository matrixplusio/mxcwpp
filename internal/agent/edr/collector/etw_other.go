//go:build !windows

package collector

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

type WindowsEventKind string

type WindowsEvent struct {
	Kind          WindowsEventKind
	PID           uint32
	ParentPID     uint32
	Image         string
	CommandLine   string
	User          string
	TimeStamp     time.Time
	DstIP         string
	DstPort       uint16
	SrcIP         string
	SrcPort       uint16
	Protocol      string
	FilePath      string
	RegistryKey   string
	RegistryValue string
	ImageHash     string
	Raw           map[string]any
}

type ETWCollector struct{}

type ETWConfig struct {
	SessionName       string
	Providers         []string
	BufferSize        int
	MinBuffers        int
	MaxBuffers        int
	IncludeStackTrace bool
}

func DefaultETWConfig() ETWConfig {
	return ETWConfig{SessionName: "mxsec-etw"}
}

func NewETWCollector(_ ETWConfig, _ *zap.Logger) *ETWCollector { return &ETWCollector{} }

func (c *ETWCollector) Events() <-chan WindowsEvent { return nil }
func (c *ETWCollector) Start(_ context.Context) error {
	return errors.New("etw: windows only")
}
func (c *ETWCollector) Stop() error { return nil }

func WMIQuery(_ string) ([]map[string]any, error) {
	return nil, errors.New("wmi: windows only")
}

func EnumProcessesWMI() ([]WindowsEvent, error) {
	return nil, errors.New("wmi: windows only")
}
