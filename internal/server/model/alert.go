// Package model 提供数据库模型定义
package model

import (
	"time"

	"gorm.io/gorm"
)

// AlertStatus 告警状态
type AlertStatus string

const (
	AlertStatusActive   AlertStatus = "active"   // 活跃告警
	AlertStatusResolved AlertStatus = "resolved" // 已解决
	AlertStatusIgnored  AlertStatus = "ignored"  // 已忽略
)

// AlertSource 告警来源常量
const (
	AlertSourceBaseline        = "baseline"         // 基线安全
	AlertSourceDetection       = "detection"        // CEL 规则检测
	AlertSourceAgent           = "agent"            // Agent 状态
	AlertSourceVulnerability   = "vulnerability"    // 漏洞管理
	AlertSourceFIM             = "fim"              // 文件完整性
	AlertSourceVirus           = "virus"            // 病毒查杀
	AlertSourceKube            = "kube"             // 容器安全
	AlertSourcePrometheusInfra = "prometheus_infra" // Prometheus 基础设施告警（webhook 入）
)

// AlertMode 告警来源时所处的运行模式。
// 对齐 docs/operating-modes.md §6 告警 schema 设计。
type AlertMode string

const (
	AlertModeObserve AlertMode = "observe" // 监听模式: 仅产告警, would_action 标注预期动作
	AlertModeProtect AlertMode = "protect" // 防护模式: 真执行处置动作
)

// Alert 告警模型
type Alert struct {
	TenantID       string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID             uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Mode           AlertMode   `gorm:"column:mode;type:varchar(20);not null;default:'observe';index" json:"mode"` // v2.0: observe / protect (对齐 docs/operating-modes.md §6)
	WouldAction    string      `gorm:"column:would_action;type:text" json:"would_action,omitempty"`               // observe 模式预期动作 (JSON)
	Action         string      `gorm:"column:action;type:text" json:"action,omitempty"`                           // protect 模式实际执行的动作 (JSON)
	ActionResult   string      `gorm:"column:action_result;type:text" json:"action_result,omitempty"`             // protect 动作执行结果 (JSON, status/error/ack)
	ATTCKTactic    string      `gorm:"column:attck_tactic;type:varchar(64)" json:"attck_tactic,omitempty"`        // ATT&CK 战术 ID
	ATTCKTechnique string      `gorm:"column:attck_technique;type:varchar(64)" json:"attck_technique,omitempty"`  // ATT&CK 技术 ID 列表 (逗号分隔)
	ResultID       string      `gorm:"column:result_id;type:varchar(128);not null;uniqueIndex" json:"result_id"`  // 关联 scan_results.result_id
	HostID         string      `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	RuleID         string      `gorm:"column:rule_id;type:varchar(64);not null;index" json:"rule_id"`
	PolicyID       string      `gorm:"column:policy_id;type:varchar(64);index" json:"policy_id"`
	Source         string      `gorm:"column:source;type:varchar(20);not null;default:'';index" json:"source"` // 告警来源: baseline, edr, agent, vulnerability, fim, virus, kube
	Severity       string      `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`        // critical, high, medium, low
	Category       string      `gorm:"column:category;type:varchar(50);index" json:"category"`
	Title          string      `gorm:"column:title;type:varchar(255);not null" json:"title"`
	Description    string      `gorm:"column:description;type:text" json:"description"`
	Actual         string      `gorm:"column:actual;type:text" json:"actual"`
	Expected       string      `gorm:"column:expected;type:text" json:"expected"`
	FixSuggestion  string      `gorm:"column:fix_suggestion;type:text" json:"fix_suggestion"`
	Status         AlertStatus `gorm:"column:status;type:varchar(20);not null;default:'active';index" json:"status"`
	FirstSeenAt    LocalTime   `gorm:"column:first_seen_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"first_seen_at"` // 首次发现时间
	LastSeenAt     LocalTime   `gorm:"column:last_seen_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"last_seen_at"`   // 最后发现时间
	HitCount       int         `gorm:"column:hit_count;type:int;default:1" json:"hit_count"`                                        // 累计命中次数（去重计数）
	LastNotifiedAt *LocalTime  `gorm:"column:last_notified_at;type:timestamp" json:"last_notified_at"`                              // 上次通知时间（用于定期告警）
	NotifyCount    int         `gorm:"column:notify_count;type:int;default:0" json:"notify_count"`                                  // 通知次数
	ResolvedAt     *LocalTime  `gorm:"column:resolved_at;type:timestamp" json:"resolved_at"`                                        // 解决时间
	ResolvedBy     string      `gorm:"column:resolved_by;type:varchar(100)" json:"resolved_by"`                                     // 解决人
	ResolveReason  string      `gorm:"column:resolve_reason;type:text" json:"resolve_reason"`                                       // 解决原因
	CreatedAt      LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt      LocalTime   `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`

	// 关联关系
	Host Host `gorm:"foreignKey:HostID;references:HostID" json:"host,omitempty"`
	Rule Rule `gorm:"foreignKey:RuleID;references:RuleID" json:"rule,omitempty"`
}

// TableName 指定表名
func (Alert) TableName() string {
	return "alerts"
}

// AfterCreate / AfterUpdate GORM hook 自动同步到 ClickHouse
// 仅当 ChConn 已注入（manager 启动后）才同步；失败 log 不抛错。
func (a *Alert) AfterCreate(tx *gorm.DB) error {
	syncAlertToCH(a)
	return nil
}

func (a *Alert) AfterUpdate(tx *gorm.DB) error {
	syncAlertToCH(a)
	return nil
}

func (a *Alert) AfterSave(tx *gorm.DB) error {
	syncAlertToCH(a)
	return nil
}

// syncAlertToCH 把 Alert INSERT 到 CH alerts 表（ReplacingMergeTree by result_id）。
// 每次状态变更增 version（unix nano），CH 合并保留最新。
func syncAlertToCH(a *Alert) {
	if !chSyncOpen || a == nil {
		return
	}
	ctx, cancel := chCtx()
	defer cancel()
	err := chConn.Exec(ctx, `
		INSERT INTO alerts (
			id, result_id, host_id, rule_id, policy_id, source, severity, category,
			title, description, actual, expected, fix_suggestion, status,
			first_seen_at, last_seen_at, hit_count, last_notified_at, notify_count,
			resolved_at, resolved_by, resolve_reason, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)
	`,
		uint64(a.ID), a.ResultID, a.HostID, a.RuleID, a.PolicyID, a.Source, a.Severity, a.Category,
		a.Title, a.Description, a.Actual, a.Expected, a.FixSuggestion, string(a.Status),
		time.Time(a.FirstSeenAt), time.Time(a.LastSeenAt), uint32(a.HitCount),
		asTime(a.LastNotifiedAt), uint32(a.NotifyCount),
		asTime(a.ResolvedAt), a.ResolvedBy, a.ResolveReason,
		time.Time(a.CreatedAt), time.Time(a.UpdatedAt), nowVersion(),
	)
	if err != nil {
		chLogError("alerts", err)
	}
}
