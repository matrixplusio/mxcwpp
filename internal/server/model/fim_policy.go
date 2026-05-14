package model

import "database/sql/driver"

// WatchPath FIM 监控路径配置
type WatchPath struct {
	Path    string `json:"path"`
	Level   string `json:"level"`   // NORMAL, CONTENT, PERMS
	Comment string `json:"comment"` // 说明
}

// WatchPaths FIM 监控路径列表
type WatchPaths []WatchPath

// Value 实现 driver.Valuer 接口
func (w WatchPaths) Value() (driver.Value, error) { return JSONValue(w) }

// Scan 实现 sql.Scanner 接口
func (w *WatchPaths) Scan(value any) error { return JSONScan(w, value) }

// FIMPolicy FIM 策略模型
type FIMPolicy struct {
	PolicyID             string       `gorm:"primaryKey;column:policy_id;type:varchar(64);not null" json:"policy_id"`
	Name                 string       `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Description          string       `gorm:"column:description;type:text" json:"description"`
	WatchPaths           WatchPaths   `gorm:"column:watch_paths;type:json;not null" json:"watch_paths"`
	ExcludePaths         StringArray  `gorm:"column:exclude_paths;type:json" json:"exclude_paths"`
	CheckIntervalHours   int          `gorm:"column:check_interval_hours;type:int;default:24" json:"check_interval_hours"`
	TargetType           string       `gorm:"column:target_type;type:varchar(20);default:'all'" json:"target_type"`
	TargetConfig         TargetConfig `gorm:"column:target_config;type:json" json:"target_config"`
	EscalationTimeoutMin int          `gorm:"column:escalation_timeout_min;type:int;default:1440" json:"escalation_timeout_min"`
	Enabled              bool         `gorm:"column:enabled;type:tinyint(1);default:1" json:"enabled"`
	CreatedAt            LocalTime    `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt            LocalTime    `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (FIMPolicy) TableName() string {
	return "fim_policies"
}
