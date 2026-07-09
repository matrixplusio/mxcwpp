// Package model 提供数据库模型定义
package model

// 安全事件(Incident)状态。
const (
	IncidentStatusActive        = "active"
	IncidentStatusInvestigating = "investigating"
	IncidentStatusResolved      = "resolved"
)

// Incident 安全事件：把同主机、同时间窗内的多源信号(CEL 告警 + BDE 行为异常 + storyline)
// 关联成一个事件，按 ATT&CK 战术阶段排列，聚合风险。对齐 XDR「碎片告警 → 攻击链事件」。
//
// 关联层覆盖在 alerts 之上，不改动 storyline 引擎；每主机至多一条 active incident，
// 新信号并入、按 kill-chain 推进抬升风险。
type Incident struct {
	TenantID   string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	IncidentID string `gorm:"column:incident_id;type:varchar(128);uniqueIndex;not null" json:"incident_id"` // 格式 "inc-{64位host_id}-{unix秒}"，长 79 字符，需 >64

	HostID    string  `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Hostname  string  `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	Status    string  `gorm:"column:status;type:varchar(20);not null;default:'active';index" json:"status"`
	Severity  string  `gorm:"column:severity;type:varchar(20);index" json:"severity"`      // 成员最高级别
	RiskScore float64 `gorm:"column:risk_score;type:decimal(5,1);index" json:"risk_score"` // 聚合风险(成员 max + 多战术 boost)

	Tactics     string `gorm:"column:tactics;type:varchar(255)" json:"tactics"` // 逗号分隔、按 kill-chain 排序的 ATT&CK 战术 ID
	TacticCount int    `gorm:"column:tactic_count" json:"tactic_count"`

	AlertIDs           StringArray `gorm:"column:alert_ids;type:json" json:"alert_ids"` // 成员 CEL/告警 ID
	AlertCount         int         `gorm:"column:alert_count" json:"alert_count"`
	BehaviorAlertCount int         `gorm:"column:behavior_alert_count" json:"behavior_alert_count"`
	StorylineIDs       StringArray `gorm:"column:storyline_ids;type:json" json:"storyline_ids"`

	Title   string `gorm:"column:title;type:varchar(255)" json:"title"`
	Summary string `gorm:"column:summary;type:text" json:"summary"`

	FirstSeenAt LocalTime  `gorm:"column:first_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"first_seen_at"`
	LastSeenAt  LocalTime  `gorm:"column:last_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"last_seen_at"`
	ResolvedAt  *LocalTime `gorm:"column:resolved_at;type:timestamp" json:"resolved_at"`
	ResolvedBy  string     `gorm:"column:resolved_by;type:varchar(100)" json:"resolved_by"`
	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (Incident) TableName() string {
	return "incidents"
}
