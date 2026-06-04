// Package model 提供数据库模型定义
package model

// AlertWhitelist 告警白名单模型
// 匹配规则：各字段为空或"*"表示匹配所有，非空则精确匹配。
// SourceIPCIDR 是非告警维度的扩展字段，用于 ScanDetector 等需要按
// 源 IP 段豁免的检测器（如 k8s/GKE node pool 健康探测）。
type AlertWhitelist struct {
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string    `gorm:"column:name;type:varchar(100);not null" json:"name"`           // 白名单描述名称
	RuleID       string    `gorm:"column:rule_id;type:varchar(64)" json:"rule_id"`               // 空或*表示匹配所有规则
	HostID       string    `gorm:"column:host_id;type:varchar(64)" json:"host_id"`               // 空或*表示匹配所有主机
	Category     string    `gorm:"column:category;type:varchar(50)" json:"category"`             // 空或*表示匹配所有类别
	Severity     string    `gorm:"column:severity;type:varchar(20)" json:"severity"`             // 空或*表示匹配所有级别
	SourceIPCIDR string    `gorm:"column:source_ip_cidr;type:varchar(64)" json:"source_ip_cidr"` // 源 IP CIDR（如 10.170.2.0/24），供 ScanDetector 等使用
	Reason       string    `gorm:"column:reason;type:text" json:"reason"`                        // 加入白名单的原因
	CreatedBy    string    `gorm:"column:created_by;type:varchar(100)" json:"created_by"`        // 创建人
	CreatedAt    LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt    LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (AlertWhitelist) TableName() string {
	return "alert_whitelists"
}

// Matches 判断白名单条目是否匹配告警
func (w *AlertWhitelist) Matches(ruleID, hostID, category, severity string) bool {
	if !matchField(w.RuleID, ruleID) {
		return false
	}
	if !matchField(w.HostID, hostID) {
		return false
	}
	if !matchField(w.Category, category) {
		return false
	}
	if !matchField(w.Severity, severity) {
		return false
	}
	return true
}

// matchField 判断白名单字段是否匹配目标值（空或"*"匹配所有）
func matchField(whitelistVal, targetVal string) bool {
	if whitelistVal == "" || whitelistVal == "*" {
		return true
	}
	return whitelistVal == targetVal
}
