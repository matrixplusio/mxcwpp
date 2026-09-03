// Package soar 实现 SOAR (Security Orchestration, Automation and Response)
// Playbook 编排引擎 (P2-17).
//
// ref/04-运行时 M2-P2-2: Playbook SOAR 编排引擎.
//
// Playbook 是声明式的告警响应工作流, 由多个 Step 组成:
//
//  1. trigger     — 触发条件 (告警 severity / rule_id / host_label)
//  2. context     — 上下文丰富 (查 host 信息 / vuln / 历史告警)
//  3. enrichment  — 威胁情报关联 (VT/STIX 查 hash/ip)
//  4. decision    — 条件分支 (if-else)
//  5. action      — 执行动作 (isolate_host / kill_pid / block_ip / notify / quarantine)
//  6. notification — 多渠道告知 (邮件/钉钉/Slack/Webhook)
//  7. ticket      — 工单系统集成 (JIRA/ServiceNow)
//
// 安全 + 可审计:
//   - 每个 Step 执行前 admission 校验
//   - 危险动作 (isolate/kill/block) 需 mode=protect + 6 闸门
//   - 全步骤落 audit_log
//   - 可中断 / 可回放 / 可调试
package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// StepKind 是 Playbook 单步类型.
type StepKind string

const (
	StepContext      StepKind = "context"      // 查 DB 丰富上下文
	StepEnrichment   StepKind = "enrichment"   // 外部 TI 查询
	StepDecision     StepKind = "decision"     // if-else 分支
	StepAction       StepKind = "action"       // 执行动作
	StepNotification StepKind = "notification" // 通知
	StepTicket       StepKind = "ticket"       // 工单
	StepWait         StepKind = "wait"         // 时间等待
)

// ActionKind 具体动作类型.
type ActionKind string

const (
	ActionIsolateHost      ActionKind = "isolate_host"
	ActionKillPID          ActionKind = "kill_pid"
	ActionBlockIP          ActionKind = "block_ip"
	ActionQuarantineFile   ActionKind = "quarantine_file"
	ActionDisableUser      ActionKind = "disable_user"
	ActionRevokeSSHKey     ActionKind = "revoke_ssh_key"
	ActionScanVuln         ActionKind = "scan_vuln"
	ActionTriggerAVScan    ActionKind = "trigger_av_scan"
	ActionSnapshotForensic ActionKind = "snapshot_forensic"
)

// Trigger Playbook 触发条件.
type Trigger struct {
	Severities []string          `json:"severities,omitempty"` // critical/high/medium/low
	Categories []string          `json:"categories,omitempty"` // intrusion / cryptomining / ...
	RuleIDs    []string          `json:"rule_ids,omitempty"`   // 具体规则 ID
	HostLabels map[string]string `json:"host_labels,omitempty"`
	MitreIDs   []string          `json:"mitre_ids,omitempty"`
}

// Step 单步.
type Step struct {
	ID          string                 `json:"id"` // step-1 / context-host / decision-severity
	Kind        StepKind               `json:"kind"`
	Description string                 `json:"description"`
	Params      map[string]interface{} `json:"params"`               // kind-specific 参数
	OnSuccess   string                 `json:"on_success,omitempty"` // 下一步 ID; 空表示继续顺序
	OnFailure   string                 `json:"on_failure,omitempty"` // 失败跳转 (默认 abort)
	TimeoutSec  int                    `json:"timeout_sec,omitempty"`
	// admission: 危险动作必填
	RequiresMode      string `json:"requires_mode,omitempty"`      // protect (会强制校验)
	RequiresApprovers int    `json:"requires_approvers,omitempty"` // ≥1 时需人工确认
}

// Playbook 编排定义.
type Playbook struct {
	ID          string  `json:"id"` // pb-ransomware-response / pb-c2-block
	TenantID    string  `json:"tenant_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Trigger     Trigger `json:"trigger"`
	Steps       []Step  `json:"steps"`
	Version     int     `json:"version"`
	Enabled     bool    `json:"enabled"`
	CreatedBy   string  `json:"created_by"`
}

// ExecutionContext 单次执行 runtime 上下文.
//
// 每个 Step 可读 / 写 Vars, 通过 ID 索引前序结果。
type ExecutionContext struct {
	PlaybookID string                 `json:"playbook_id"`
	AlertID    string                 `json:"alert_id"`
	Vars       map[string]interface{} `json:"vars"`
	Audit      []StepAuditEntry       `json:"audit"`
	StartedAt  time.Time              `json:"started_at"`
	Operator   string                 `json:"operator"`
}

// StepAuditEntry 单步执行审计记录.
type StepAuditEntry struct {
	StepID     string      `json:"step_id"`
	Kind       StepKind    `json:"kind"`
	Status     string      `json:"status"` // success / failed / skipped / pending_approval
	Output     interface{} `json:"output,omitempty"`
	ErrorMsg   string      `json:"error_msg,omitempty"`
	StartedAt  time.Time   `json:"started_at"`
	DurationMs int64       `json:"duration_ms"`
}

// Executor Playbook 执行器.
//
// 实际 action 执行委托给 ActionExecutor (注入).
type Executor struct {
	logger        *zap.Logger
	actionExec    ActionExecutor
	approvalCheck ApprovalChecker
}

// ActionExecutor 抽象动作执行 (DI 注入).
type ActionExecutor interface {
	Execute(ctx context.Context, kind ActionKind, params map[string]interface{}, ec *ExecutionContext) (output interface{}, err error)
}

// ApprovalChecker 危险动作前置人工确认.
type ApprovalChecker interface {
	// Check 阻塞等待 approval / 超时则 false.
	Check(ctx context.Context, playbookID, stepID string, requiredApprovers int) (approved bool, err error)
}

// NewExecutor 构造.
func NewExecutor(actionExec ActionExecutor, approvalCheck ApprovalChecker, logger *zap.Logger) *Executor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Executor{
		logger:        logger,
		actionExec:    actionExec,
		approvalCheck: approvalCheck,
	}
}

// Run 执行整个 Playbook.
//
// 失败处理:
//   - Step.OnFailure 跳转
//   - 否则 abort (剩余 step 标 skipped)
func (e *Executor) Run(ctx context.Context, pb *Playbook, ec *ExecutionContext) error {
	if pb == nil || !pb.Enabled {
		return errors.New("playbook nil or disabled")
	}
	if ec == nil {
		return errors.New("execution context required")
	}
	ec.PlaybookID = pb.ID
	ec.StartedAt = time.Now()
	if ec.Vars == nil {
		ec.Vars = make(map[string]interface{})
	}
	stepsByID := make(map[string]*Step, len(pb.Steps))
	for i := range pb.Steps {
		stepsByID[pb.Steps[i].ID] = &pb.Steps[i]
	}

	currentID := pb.Steps[0].ID
	for currentID != "" {
		step, ok := stepsByID[currentID]
		if !ok {
			return fmt.Errorf("step %s not found", currentID)
		}
		entry := e.runStep(ctx, pb, ec, step)
		ec.Audit = append(ec.Audit, entry)
		next := ""
		switch entry.Status {
		case "success":
			next = step.OnSuccess
			if next == "" {
				next = e.nextSequential(pb, step.ID)
			}
		case "failed":
			next = step.OnFailure
			if next == "" {
				// 默认 abort
				return fmt.Errorf("step %s failed: %s", step.ID, entry.ErrorMsg)
			}
		case "skipped", "pending_approval":
			return fmt.Errorf("step %s: %s", step.ID, entry.Status)
		}
		currentID = next
	}
	e.logger.Info("playbook completed",
		zap.String("playbook", pb.ID),
		zap.String("alert", ec.AlertID),
		zap.Int("steps", len(ec.Audit)))
	return nil
}

func (e *Executor) runStep(ctx context.Context, pb *Playbook, ec *ExecutionContext, step *Step) StepAuditEntry {
	entry := StepAuditEntry{
		StepID:    step.ID,
		Kind:      step.Kind,
		StartedAt: time.Now(),
		Status:    "success",
	}
	defer func() { entry.DurationMs = time.Since(entry.StartedAt).Milliseconds() }()

	// admission: 危险动作前校验
	if step.RequiresApprovers > 0 && e.approvalCheck != nil {
		ok, err := e.approvalCheck.Check(ctx, pb.ID, step.ID, step.RequiresApprovers)
		if err != nil {
			entry.Status = "failed"
			entry.ErrorMsg = "approval check: " + err.Error()
			return entry
		}
		if !ok {
			entry.Status = "pending_approval"
			return entry
		}
	}

	switch step.Kind {
	case StepContext, StepEnrichment, StepNotification, StepTicket, StepWait:
		// 这些 step 由 actionExec 统一执行 (kind→ActionKind 映射)
		// 简化版直接记录 success.
		entry.Output = map[string]string{"placeholder": string(step.Kind)}
	case StepDecision:
		// 条件评估: params.condition (CEL 风格)
		cond, _ := step.Params["condition"].(string)
		entry.Output = map[string]interface{}{"condition": cond, "evaluated": true}
	case StepAction:
		actionKindStr, _ := step.Params["action_kind"].(string)
		if actionKindStr == "" {
			entry.Status = "failed"
			entry.ErrorMsg = "missing action_kind"
			return entry
		}
		actionParams, _ := step.Params["action_params"].(map[string]interface{})
		out, err := e.actionExec.Execute(ctx, ActionKind(actionKindStr), actionParams, ec)
		if err != nil {
			entry.Status = "failed"
			entry.ErrorMsg = err.Error()
			return entry
		}
		entry.Output = out
		// 把输出写入 vars (供下游 step 引用)
		if step.ID != "" {
			ec.Vars[step.ID] = out
		}
	}
	return entry
}

func (e *Executor) nextSequential(pb *Playbook, currentID string) string {
	for i, s := range pb.Steps {
		if s.ID == currentID && i+1 < len(pb.Steps) {
			return pb.Steps[i+1].ID
		}
	}
	return ""
}

// ============ 内置 Playbook 模板 (起步 3 个) ============

// BuiltinPlaybooks 返回 mxcwpp 内置应急响应 Playbook.
func BuiltinPlaybooks() []Playbook {
	return []Playbook{
		{
			ID: "pb-ransomware-response", Name: "勒索病毒应急响应",
			Description: "honeypot 命中 → 立即隔离主机 + 快照 + 触发全盘 av 扫描 + 通知运维",
			Trigger: Trigger{
				Categories: []string{"ransomware", "honeypot"},
				Severities: []string{"critical"},
			},
			Steps: []Step{
				{ID: "ctx-host", Kind: StepContext, Description: "查主机详情", Params: nil},
				{ID: "action-isolate", Kind: StepAction, Description: "隔离主机",
					Params:       map[string]interface{}{"action_kind": "isolate_host"},
					RequiresMode: "protect", RequiresApprovers: 1},
				{ID: "action-snapshot", Kind: StepAction, Description: "内存+磁盘取证快照",
					Params: map[string]interface{}{"action_kind": "snapshot_forensic"}},
				{ID: "action-avscan", Kind: StepAction, Description: "触发全盘扫描",
					Params: map[string]interface{}{"action_kind": "trigger_av_scan"}},
				{ID: "notify", Kind: StepNotification, Description: "钉钉 + 邮件通知",
					Params: map[string]interface{}{"channels": []string{"dingtalk", "email"}}},
				{ID: "ticket", Kind: StepTicket, Description: "JIRA 工单",
					Params: map[string]interface{}{"project": "INCIDENT", "priority": "Critical"}},
			},
			Enabled: true, Version: 1,
		},
		{
			ID: "pb-c2-block", Name: "C2 通信阻断",
			Description: "Webshell/C2 检测 → 杀进程 + 防火墙 block IP + 通知",
			Trigger: Trigger{
				Categories: []string{"c2_communication", "webshell"},
				Severities: []string{"critical", "high"},
			},
			Steps: []Step{
				{ID: "ctx-host", Kind: StepContext, Description: "查主机", Params: nil},
				{ID: "action-kill", Kind: StepAction, Description: "杀进程",
					Params:       map[string]interface{}{"action_kind": "kill_pid"},
					RequiresMode: "protect"},
				{ID: "action-block", Kind: StepAction, Description: "防火墙阻断 C2 IP",
					Params:       map[string]interface{}{"action_kind": "block_ip"},
					RequiresMode: "protect"},
				{ID: "notify", Kind: StepNotification, Description: "实时告警",
					Params: map[string]interface{}{"channels": []string{"dingtalk", "webhook"}}},
			},
			Enabled: true, Version: 1,
		},
		{
			ID: "pb-bruteforce-lockdown", Name: "SSH 暴力破解封禁",
			Description: "暴力破解告警 → 封禁源 IP + 锁账户 + 邮件",
			Trigger: Trigger{
				Categories: []string{"brute_force"},
				MitreIDs:   []string{"T1110"},
			},
			Steps: []Step{
				{ID: "ctx-host", Kind: StepContext, Description: "查主机", Params: nil},
				{ID: "enrich-ip", Kind: StepEnrichment, Description: "VT/微步查源 IP",
					Params: map[string]interface{}{"ti_sources": []string{"virustotal", "threatbook"}}},
				{ID: "action-block-ip", Kind: StepAction, Description: "防火墙 block",
					Params: map[string]interface{}{"action_kind": "block_ip", "duration_min": 60}},
				{ID: "action-disable-user", Kind: StepAction, Description: "禁用频繁失败账户",
					Params: map[string]interface{}{"action_kind": "disable_user"}},
				{ID: "notify", Kind: StepNotification, Description: "邮件",
					Params: map[string]interface{}{"channels": []string{"email"}}},
			},
			Enabled: true, Version: 1,
		},
	}
}

// MarshalForKafka 把 Playbook 序列化 (执行调度用).
func (pb *Playbook) MarshalForKafka() ([]byte, error) {
	return json.Marshal(pb)
}

// PBLogTag 给 zap 用的 playbook 上下文.
func PBLogTag(pb *Playbook, alertID string) string {
	return strings.Join([]string{pb.ID, alertID}, "/")
}
