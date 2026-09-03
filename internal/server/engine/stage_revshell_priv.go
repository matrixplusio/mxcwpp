package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// ReverseShellStage 反弹 shell 检测。
type ReverseShellStage struct {
	detector *intrusion.ReverseShellDetector
	logger   *zap.Logger
}

// NewReverseShellStage 构造。
func NewReverseShellStage(d *intrusion.ReverseShellDetector, logger *zap.Logger) *ReverseShellStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = intrusion.NewReverseShellDetector()
	}
	return &ReverseShellStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *ReverseShellStage) Name() string { return "intrusion_reverse_shell" }

// Process 仅处理进程类事件 (DataType 3000-3001 process_exec)。
func (s *ReverseShellStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	if ev.DataType < 3000 || ev.DataType > 3001 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	pe := intrusion.ParseProcessEventFromFields(ev.HostID, fields)
	if pe == nil {
		return nil, nil
	}
	payload, hit := s.detector.Scan(ctx, *pe)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-revshell-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "REVERSE_SHELL",
			Severity:       "critical",
			ATTCKTactic:    "TA0011", // Command and Control
			ATTCKTechnique: "T1059",  // Command and Scripting Interpreter
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

var _ Stage = (*ReverseShellStage)(nil)

// PrivEscalationStage 本地提权检测。
type PrivEscalationStage struct {
	detector *intrusion.PrivEscalationDetector
	logger   *zap.Logger
}

// NewPrivEscalationStage 构造。
func NewPrivEscalationStage(d *intrusion.PrivEscalationDetector, logger *zap.Logger) *PrivEscalationStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = intrusion.NewPrivEscalationDetector()
	}
	return &PrivEscalationStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *PrivEscalationStage) Name() string { return "intrusion_priv_escalation" }

// Process 仅处理进程事件。
func (s *PrivEscalationStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	if ev.DataType < 3000 || ev.DataType > 3001 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	pe := intrusion.ParseProcessEventFromFields(ev.HostID, fields)
	if pe == nil {
		return nil, nil
	}
	payload, hit := s.detector.Scan(ctx, *pe)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-priv-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "PRIVILEGE_ESCALATION",
			Severity:       "critical",
			ATTCKTactic:    "TA0004", // Privilege Escalation
			ATTCKTechnique: "T1068",  // Exploitation for Privilege Escalation
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

var _ Stage = (*PrivEscalationStage)(nil)
