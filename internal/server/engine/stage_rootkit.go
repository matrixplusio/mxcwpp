package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// RootkitStage Rootkit/后门检测。
type RootkitStage struct {
	detector *intrusion.RootkitDetector
	logger   *zap.Logger
}

// NewRootkitStage 构造。
func NewRootkitStage(d *intrusion.RootkitDetector, logger *zap.Logger) *RootkitStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = intrusion.NewRootkitDetector()
	}
	return &RootkitStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *RootkitStage) Name() string { return "intrusion_rootkit" }

// Process 处理多种事件类型 (process_exec / file_create / kernel_module_load)。
func (s *RootkitStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}

	// 探测内容: 进程 cmdline / 文件路径 / kernel module 名
	content := fields["cmdline"]
	source := "process"
	if content == "" {
		content = fields["file_path"]
		source = "file"
	}
	if content == "" {
		content = fields["module_name"]
		source = "kernel_module"
	}
	if content == "" {
		return nil, nil
	}

	ie := intrusion.IndicatorEvent{
		HostID:  ev.HostID,
		Source:  source,
		Content: content,
		UID:     atoi32(fields["uid"]),
	}
	payload, hit := s.detector.Scan(ctx, ie)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-rootkit-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "ROOTKIT_BACKDOOR",
			Severity:       "critical",
			ATTCKTactic:    "TA0003", // Persistence (含 LKM rootkit 持久化)
			ATTCKTechnique: "T1547",  // Boot or Logon Autostart Execution
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

// atoi32 是 stage_rootkit 用的私有 helper。
func atoi32(s string) int32 {
	var n int32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int32(c-'0')
	}
	return n
}

var _ Stage = (*RootkitStage)(nil)
