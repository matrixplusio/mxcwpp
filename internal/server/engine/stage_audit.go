package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ConfigChangeAuditStage 处理高敏配置变更事件 → 告警 (P5-5).
//
// Data flow:
//
//	ConfigChangeWorker.applySystemConfig / applyKubeCluster 写入 Kafka
//	  → Pipeline 收 PipelineEvent.DataType=14501 (配置变更审计)
//	  → 本 Stage 命中高敏 key → 产 Alert
//
// 高敏 key 判定:
//   - 前缀 kms.* / secret.* / password.* / token.*  → severity=critical
//   - 前缀 feature.protect / mode.* / iam.role.*    → severity=high
//   - 其它                                          → severity=info (仍上报便于审计回溯)
type ConfigChangeAuditStage struct {
	logger *zap.Logger
}

// NewConfigChangeAuditStage 构造.
func NewConfigChangeAuditStage(logger *zap.Logger) *ConfigChangeAuditStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ConfigChangeAuditStage{logger: logger}
}

// Name 满足 Stage interface.
func (s *ConfigChangeAuditStage) Name() string { return "config_change_audit" }

// configChangePayload 与 ConfigChangeWorker 写入 Kafka 的格式一致.
type configChangePayload struct {
	RequestID     uint   `json:"request_id"`
	TargetTable   string `json:"target_table"`
	TargetKey     string `json:"target_key"`
	OldValue      string `json:"old_value"`
	ProposedValue string `json:"proposed_value"`
	RequestedBy   string `json:"requested_by"`
	Approvers     string `json:"approvers"`
	AppliedAt     int64  `json:"applied_at_ms"`
}

// Process 仅处理 DataType=14501 (配置变更审计) 与 14502 (隔离箱审计).
func (s *ConfigChangeAuditStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType != 14501 {
		return nil, nil
	}
	var p configChangePayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return nil, nil
	}
	sev := classifyKey(p.TargetKey)
	alert := Alert{
		AlertID:        fmt.Sprintf("cr-%d-%d", p.RequestID, time.Now().UnixNano()),
		RuleID:         "config-change-audit",
		Severity:       sev,
		ATTCKTactic:    "TA0003", // Persistence
		ATTCKTechnique: "T1098",  // Account Manipulation (映射到配置变更)
		Payload:        ev.Payload,
	}
	return []Alert{alert}, nil
}

func classifyKey(key string) string {
	k := strings.ToLower(key)
	for _, prefix := range []string{"kms.", "secret.", "password.", "token."} {
		if strings.HasPrefix(k, prefix) {
			return "critical"
		}
	}
	if strings.HasPrefix(k, "feature.protect") ||
		strings.HasPrefix(k, "mode.") ||
		strings.HasPrefix(k, "iam.role.") ||
		strings.HasPrefix(k, "rbac.") {
		return "high"
	}
	return "info"
}

// QuarantineAuditStage 处理隔离箱事件 → 告警.
//
// 隔离意味检测到 webshell / virus / suspicious 文件, 默认 high 严重.
// 还原操作 → medium (可能是误报恢复).
type QuarantineAuditStage struct {
	logger *zap.Logger
}

// NewQuarantineAuditStage 构造.
func NewQuarantineAuditStage(logger *zap.Logger) *QuarantineAuditStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &QuarantineAuditStage{logger: logger}
}

// Name 满足 Stage interface.
func (s *QuarantineAuditStage) Name() string { return "quarantine_audit" }

// quarantinePayload 与 quarantine Worker 写入 Kafka 的格式一致.
type quarantinePayload struct {
	QID       string `json:"qid"`
	HostID    string `json:"host_id"`
	OrigPath  string `json:"orig_path"`
	Hash      string `json:"hash"`
	Reason    string `json:"reason"`
	Operation string `json:"operation"` // quarantine | restore
	RuleID    string `json:"rule_id"`
}

// Process 处理 DataType=14502 (隔离箱审计).
func (s *QuarantineAuditStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType != 14502 {
		return nil, nil
	}
	var p quarantinePayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return nil, nil
	}
	sev := "high"
	if p.Operation == "restore" {
		sev = "medium"
	}
	tac, tech := "TA0040", "T1486"
	if strings.Contains(strings.ToLower(p.Reason), "webshell") {
		tac, tech = "TA0001", "T1190" // Initial Access / Public-Facing App
	}
	alert := Alert{
		AlertID:        fmt.Sprintf("q-%s-%d", p.QID, time.Now().UnixNano()),
		RuleID:         "quarantine-audit-" + p.Operation,
		Severity:       sev,
		ATTCKTactic:    tac,
		ATTCKTechnique: tech,
		Payload:        ev.Payload,
	}
	return []Alert{alert}, nil
}
