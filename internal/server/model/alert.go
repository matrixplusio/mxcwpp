// Package model 提供数据库模型定义
package model

// AlertStatus 告警状态
type AlertStatus string

const (
	AlertStatusActive   AlertStatus = "active"   // 活跃告警
	AlertStatusResolved AlertStatus = "resolved" // 已解决
	AlertStatusIgnored  AlertStatus = "ignored"  // 已忽略
)

// AlertSource 告警来源常量
const (
	AlertSourceBaseline      = "baseline"      // 基线安全
	AlertSourceEDR           = "edr"           // EDR 检测
	AlertSourceAgent         = "agent"         // Agent 状态
	AlertSourceVulnerability = "vulnerability" // 漏洞管理
	AlertSourceFIM           = "fim"           // 文件完整性
	AlertSourceVirus         = "virus"         // 病毒查杀
	AlertSourceKube          = "kube"          // 容器安全
)

// Alert 告警模型
type Alert struct {
	ID             uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ResultID       string      `gorm:"column:result_id;type:varchar(128);not null;uniqueIndex" json:"result_id"` // 关联 scan_results.result_id
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
