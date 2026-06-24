package engine

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/honeypot"
)

// HoneypotStage 反勒索 honeypot 检测。
//
// 仅处理 DataType 7020-7029 (Agent av-scanner 上报的 honeypot 触发事件)。
type HoneypotStage struct {
	detector *honeypot.Detector
	logger   *zap.Logger
}

// NewHoneypotStage 构造。
func NewHoneypotStage(d *honeypot.Detector, logger *zap.Logger) *HoneypotStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = honeypot.NewDetector()
	}
	return &HoneypotStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *HoneypotStage) Name() string { return "anti_ransom_honeypot" }

// Process 仅处理 honeypot 类事件。
func (s *HoneypotStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	if ev.DataType < 7020 || ev.DataType > 7029 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	t := honeypot.HoneypotTrigger{
		HostID:        ev.HostID,
		DecoyPath:     fields["decoy_path"],
		DecoyType:     fields["decoy_type"],
		TriggeringPID: atoi32(fields["pid"]),
		TriggeringExe: fields["exe"],
		TriggeringUID: atoi32(fields["uid"]),
		Operation:     fields["operation"],
		Timestamp:     time.Now(),
	}
	payload := s.detector.Evaluate(ctx, t)
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-ransom-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "RANSOMWARE_HONEYPOT",
			Severity:       "critical",
			ATTCKTactic:    "TA0040", // Impact
			ATTCKTechnique: "T1486",  // Data Encrypted for Impact
			Payload:        payload,
			WouldAction:    payload,
			Action:         payload,
		},
	}, nil
}

var _ Stage = (*HoneypotStage)(nil)
