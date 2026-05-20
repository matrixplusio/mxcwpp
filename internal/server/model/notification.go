// Package model 提供数据库模型定义
package model

import "database/sql/driver"

// NotificationType 通知类型
type NotificationType string

const (
	NotificationTypeLark    NotificationType = "lark"    // 飞书
	NotificationTypeWebhook NotificationType = "webhook" // Webhook
)

// NotificationScope 主机范围类型
type NotificationScope string

const (
	NotificationScopeGlobal       NotificationScope = "global"        // 全局
	NotificationScopeHostTags     NotificationScope = "host_tags"     // 主机标签
	NotificationScopeBusinessLine NotificationScope = "business_line" // 业务线
	NotificationScopeSpecified    NotificationScope = "specified"     // 指定主机
)

// NotifyCategory 通知类别
type NotifyCategory string

const (
	NotifyCategoryBaselineAlert NotifyCategory = "baseline_alert" // 基线告警通知
	NotifyCategoryAgentOffline  NotifyCategory = "agent_offline"  // Agent 离线通知
	NotifyCategoryVirusAlert    NotifyCategory = "virus_alert"    // 病毒查杀告警通知
	NotifyCategoryFIMAlert      NotifyCategory = "fim_alert"      // 文件完整性告警通知
	NotifyCategoryEDRAlert      NotifyCategory = "edr_alert"      // EDR 告警通知
	NotifyCategoryKubeAlert     NotifyCategory = "kube_alert"     // K8s 安全告警通知
	NotifyCategoryVulnBulletin  NotifyCategory = "vuln_bulletin"  // 漏洞通报通知
)

// NotificationSeverity 通知等级
type NotificationSeverity string

const (
	NotificationSeverityCritical NotificationSeverity = "critical" // 严重
	NotificationSeverityHigh     NotificationSeverity = "high"     // 高危
	NotificationSeverityMedium   NotificationSeverity = "medium"   // 中危
	NotificationSeverityLow      NotificationSeverity = "low"      // 低危
)

// NotificationConfig 通知配置（JSON 格式）
type NotificationConfig struct {
	// Lark 配置
	WebhookURL string `json:"webhook_url,omitempty"` // Webhook URL（Lark 和通用 Webhook 共用）
	Secret     string `json:"secret,omitempty"`      // Secret（用于签名验证）
	UserNotes  string `json:"user_notes,omitempty"`  // 用户备注
}

// Value 实现 driver.Valuer 接口
func (c NotificationConfig) Value() (driver.Value, error) { return JSONValue(c) }

// Scan 实现 sql.Scanner 接口
func (c *NotificationConfig) Scan(value any) error { return JSONScan(c, value) }

// Notification 通知配置模型
type Notification struct {
	ID             uint               `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name           string             `gorm:"column:name;type:varchar(100);not null" json:"name"`                            // 通知名称（自定义名称）
	Description    string             `gorm:"column:description;type:text" json:"description"`                               // 描述
	NotifyCategory NotifyCategory     `gorm:"column:notify_category;type:varchar(30);not null;index" json:"notify_category"` // 通知类别（baseline_alert/agent_offline）
	Enabled        bool               `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`                       // 是否启用
	Type           NotificationType   `gorm:"column:type;type:varchar(20);not null" json:"type"`                             // 通知类型（lark/webhook）
	Severities     StringArray        `gorm:"column:severities;type:json" json:"severities"`                                 // 通知等级（仅基线告警：critical、high、medium、low）
	Scope          NotificationScope  `gorm:"column:scope;type:varchar(20);not null;default:'global'" json:"scope"`          // 主机范围类型
	ScopeValue     string             `gorm:"column:scope_value;type:text" json:"scope_value"`                               // 主机范围值（JSON，根据 scope 类型存储不同数据）
	FrontendURL    string             `gorm:"column:frontend_url;type:varchar(500)" json:"frontend_url"`                     // 前端地址（告警带上告警uri）
	Config         NotificationConfig `gorm:"column:config;type:json" json:"config"`                                         // 通知配置（Webhook URL、Secret 等）
	CreatedAt      LocalTime          `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt      LocalTime          `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (Notification) TableName() string {
	return "notifications"
}

// ScopeValueData 主机范围值数据结构
type ScopeValueData struct {
	// 当 scope = "host_tags" 时
	Tags []string `json:"tags,omitempty"` // 主机标签列表

	// 当 scope = "business_line" 时
	BusinessLines []string `json:"business_lines,omitempty"` // 业务线列表

	// 当 scope = "specified" 时
	HostIDs []string `json:"host_ids,omitempty"` // 指定主机ID列表
}
