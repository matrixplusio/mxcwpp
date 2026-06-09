package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/rasp"
)

// RASPStage 处理 Agent 上报的 RASP 事件 (Java/PHP/Python/Node)。
//
// 严格 read-only:
//   - 永远只产 Alert (告警 + storyline 关联)
//   - 不下发 action_kill / action_throw_exception 等阻断指令
//   - mode 字段在落 Kafka 前被 EnsureObserveMode 强制改 observe
//   - 即便全局 mode.Resolver=protect, RASP 仍走 observe 路径
//
// DataType 段: 4000-4099 (RASP 事件, Agent 上报)
type RASPStage struct {
	logger *zap.Logger
}

// NewRASPStage 构造。
func NewRASPStage(logger *zap.Logger) *RASPStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &RASPStage{logger: logger}
}

// Name 满足 Stage interface。
func (s *RASPStage) Name() string { return "rasp_observe" }

// Process 仅处理 RASP DataType 段。
func (s *RASPStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType < 4000 || ev.DataType > 4099 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	raspEv := rasp.ParseFromFields(ev.HostID, ev.TenantID, ev.AgentID, fields)
	if raspEv == nil {
		return nil, nil
	}
	raspEv.EnsureObserveMode() // 哲学硬约束

	// 内存马规则 (Java)
	hits := rasp.MemshellIndicators(*raspEv)

	// PHP 危险函数 + 可疑参数 (PR71)
	if raspEv.Language == "php" {
		if desc, isDanger := rasp.PHPDangerousFunctions[raspEv.MethodName]; isDanger {
			hits = append(hits, "php_dangerous_fn:"+raspEv.MethodName+":"+desc)
		}
		hits = append(hits, rasp.PHPSuspiciousArgs(raspEv.MethodName, raspEv.Arguments)...)
	}

	// Python 危险 audit + 反弹 shell 链 (PR71)
	if raspEv.Language == "python" {
		if desc, isDanger := rasp.PythonDangerousAudits[raspEv.MethodName]; isDanger {
			hits = append(hits, "python_audit:"+raspEv.MethodName+":"+desc)
		}
		if sus := rasp.PythonSuspiciousImport(raspEv.ClassName); sus != "" {
			hits = append(hits, sus)
		}
		if rasp.PythonReverseShellPattern(raspEv.StackTrace) {
			hits = append(hits, "python_reverse_shell_pattern")
		}
	}

	if len(hits) == 0 {
		// 非内存马 / 非语言特定命中: 仅其他高危类型才产 Alert
		if !isHighRiskKind(raspEv.Kind) {
			return nil, nil
		}
	}

	payload, _ := json.Marshal(map[string]any{
		"language":      raspEv.Language,
		"kind":          raspEv.Kind,
		"class_name":    raspEv.ClassName,
		"method_name":   raspEv.MethodName,
		"http":          raspEv.HTTPContext,
		"stack":         raspEv.StackTrace,
		"args":          raspEv.Arguments,
		"memshell_hits": hits,
		// 始终 observe,不下 action
		"would_action": map[string]any{
			"type":   "alert_only",
			"reason": "RASP observe 模式: 仅告警, 不阻断业务",
		},
	})

	severity := "medium"
	rule := "RASP_HIGH_RISK_CALL"
	switch {
	case len(hits) > 0 && raspEv.Language == "java":
		severity = "critical"
		rule = "JAVA_MEMSHELL"
	case len(hits) > 0 && raspEv.Language == "php":
		severity = "high"
		rule = "PHP_DANGEROUS_CALL"
	case len(hits) > 0 && raspEv.Language == "python":
		severity = "high"
		rule = "PYTHON_DANGEROUS_CALL"
	}

	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-rasp-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         rule,
			Severity:       severity,
			ATTCKTactic:    "TA0002", // Execution
			ATTCKTechnique: "T1059",  // Command and Scripting Interpreter
			Payload:        payload,
			WouldAction:    payload,
			// 注意: Action 字段保持 nil; RASP 不参与 protect 模式
			Action: nil,
		},
	}, nil
}

// isHighRiskKind 判断 RASP kind 是否高危需要告警。
func isHighRiskKind(k rasp.EventKind) bool {
	switch k {
	case rasp.KindJavaDeserialize,
		rasp.KindJavaReflection,
		rasp.KindJavaMemshell,
		rasp.KindPHPEval,
		rasp.KindPHPSystemCall,
		rasp.KindPyExec,
		rasp.KindPySubprocess,
		rasp.KindNodeChildProcess:
		return true
	}
	return false
}

var _ Stage = (*RASPStage)(nil)
