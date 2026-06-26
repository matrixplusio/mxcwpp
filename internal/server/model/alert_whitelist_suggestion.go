// Package model 提供数据库模型定义
package model

// 自动调优建议状态（P2-B）
const (
	SuggestionStatusPending   = "pending"   // 待人审
	SuggestionStatusAdopted   = "adopted"   // 已采纳（写入 AlertWhitelist）
	SuggestionStatusDismissed = "dismissed" // 已驳回
)

// AlertWhitelistSuggestion 自动调优建议（P2-B）。
//
// 由 manager 端 AutoTuningScheduler 聚合近期被 resolve/ignore 的告警生成：
// 某 (rule_id, exe) 模式被反复判误报且当前无对应 active 真阳，则生成一条 pending 建议。
// 分析师在 UI 一键采纳 → 写入 AlertWhitelist（人审才生效，不自动制造检测盲区）。
type AlertWhitelistSuggestion struct {
	TenantID  string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Signature string `gorm:"column:signature;type:varchar(255);not null;uniqueIndex" json:"signature"` // 去重键 rule_id|exe|cmdline|host_id

	RuleID   string `gorm:"column:rule_id;type:varchar(64);not null;index" json:"rule_id"`
	RuleName string `gorm:"column:rule_name;type:varchar(200)" json:"rule_name"`
	HostID   string `gorm:"column:host_id;type:varchar(64)" json:"host_id"`  // 空=全队列（fleet-wide exe 豁免）
	Exe      string `gorm:"column:exe;type:varchar(255)" json:"exe"`         // 建议豁免的进程 basename
	Cmdline  string `gorm:"column:cmdline;type:varchar(500)" json:"cmdline"` // 建议豁免的命令行子串（可空）
	Category string `gorm:"column:category;type:varchar(50)" json:"category"`
	Severity string `gorm:"column:severity;type:varchar(20)" json:"severity"`

	HitCount            int         `gorm:"column:hit_count;type:int;not null;default:0;index" json:"hit_count"`   // 命中（被 resolve/ignore）次数
	Confidence          int         `gorm:"column:confidence;type:int;not null;default:0;index" json:"confidence"` // 置信度 0-100
	SampleAlertIDs      StringArray `gorm:"column:sample_alert_ids;type:json" json:"sample_alert_ids"`             // 示例告警 ID（取证溯源）
	ResolveReasonSample string      `gorm:"column:resolve_reason_sample;type:text" json:"resolve_reason_sample"`   // 代表性 resolve_reason

	Status      string     `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	DecidedBy   string     `gorm:"column:decided_by;type:varchar(100)" json:"decided_by"`     // 采纳/驳回人
	DecidedAt   *LocalTime `gorm:"column:decided_at;type:timestamp" json:"decided_at"`        // 采纳/驳回时间
	WhitelistID uint       `gorm:"column:whitelist_id;type:int unsigned" json:"whitelist_id"` // 采纳后生成的 AlertWhitelist ID

	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (AlertWhitelistSuggestion) TableName() string {
	return "alert_whitelist_suggestions"
}
