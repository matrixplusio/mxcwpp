package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
)

// AntiRootkitStage 处理 Agent 端 Anti-Rootkit Scanner 上报 (P1-4).
//
// 与 RootkitStage 区别:
//
//	RootkitStage     — 接 process/file/kmod 事件做模式匹配 (用户态 cmdline)
//	AntiRootkitStage — 接 Agent rootkit/scanner.go 周期 5min 自检结果 (内核完整性)
//
// DataType 3006 (Agent rootkit/scanner.go 周期上报):
//
//	kmod_hidden        — /proc/modules vs /sys/module 差异
//	known_rootkit_kmod — /proc/modules 命中已知 rootkit 名
//	syscall_drift      — sys_call_table 地址变化
//	pid_hidden         — /proc PID 列表与 getdents 差异
type AntiRootkitStage struct {
	logger *zap.Logger
}

// NewAntiRootkitStage 构造.
func NewAntiRootkitStage(logger *zap.Logger) *AntiRootkitStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AntiRootkitStage{logger: logger}
}

// Name 满足 Stage interface.
func (s *AntiRootkitStage) Name() string { return "anti_rootkit" }

// Process 处理 DataType 3006 事件。
func (s *AntiRootkitStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType != 3006 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	category := fields["category"]
	if category == "" {
		return nil, nil
	}

	severity := fields["severity"]
	if severity == "" {
		severity = "high"
	}

	rule := "ROOTKIT_INDICATOR"
	tactic := "TA0005" // Defense Evasion
	technique := "T1014"
	detail := fields["detail"]

	switch category {
	case "kmod_hidden":
		rule = "ROOTKIT_KMOD_HIDDEN"
		severity = "critical"
		technique = "T1014"
	case "known_rootkit_kmod":
		rule = "ROOTKIT_KNOWN_LKM"
		severity = "critical"
		technique = "T1547.006"
		tactic = "TA0003"
	case "syscall_drift":
		rule = "ROOTKIT_SYSCALL_DRIFT"
		technique = "T1014"
	case "pid_hidden":
		rule = "ROOTKIT_PID_HIDDEN"
		severity = "high"
		technique = "T1014"
	}

	payload, _ := json.Marshal(map[string]any{
		"category":     category,
		"severity":     severity,
		"detail":       detail,
		"evidence":     fields,
		"would_action": map[string]any{"type": "alert_only"},
	})

	return []Alert{{
		AlertID:        fmt.Sprintf("alrt-antirootkit-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
		RuleID:         rule,
		Severity:       severity,
		ATTCKTactic:    tactic,
		ATTCKTechnique: technique,
		Payload:        payload,
		WouldAction:    payload,
	}}, nil
}

var _ Stage = (*AntiRootkitStage)(nil)
