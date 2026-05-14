package model

import "database/sql/driver"

// ChangeDetail FIM 变更详情
type ChangeDetail struct {
	SizeBefore        string `json:"size_before,omitempty"`
	SizeAfter         string `json:"size_after,omitempty"`
	HashBefore        string `json:"hash_before,omitempty"`
	HashAfter         string `json:"hash_after,omitempty"`
	ModeBefore        string `json:"mode_before,omitempty"`
	ModeAfter         string `json:"mode_after,omitempty"`
	HashChanged       bool   `json:"hash_changed"`
	PermissionChanged bool   `json:"permission_changed"`
	OwnerChanged      bool   `json:"owner_changed"`
	Attributes        string `json:"attributes,omitempty"`
}

// Value 实现 driver.Valuer 接口
func (c ChangeDetail) Value() (driver.Value, error) { return JSONValue(c) }

// Scan 实现 sql.Scanner 接口
func (c *ChangeDetail) Scan(value any) error { return JSONScan(c, value) }

// FIMEvent FIM 变更事件模型
type FIMEvent struct {
	EventID       string       `gorm:"primaryKey;column:event_id;type:varchar(64);not null" json:"event_id"`
	HostID        string       `gorm:"column:host_id;type:varchar(64);not null;index:idx_fim_event_host_id" json:"host_id"`
	Hostname      string       `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	TaskID        string       `gorm:"column:task_id;type:varchar(64)" json:"task_id"`
	FilePath      string       `gorm:"column:file_path;type:varchar(1024);not null;index:idx_fim_event_file_path,length:255" json:"file_path"`
	ChangeType    string       `gorm:"column:change_type;type:varchar(20);not null" json:"change_type"` // added/removed/changed
	ChangeDetail  ChangeDetail `gorm:"column:change_detail;type:json" json:"change_detail"`
	Severity      string       `gorm:"column:severity;type:varchar(20);default:'medium';index:idx_fim_event_severity" json:"severity"`
	Category      string       `gorm:"column:category;type:varchar(50)" json:"category"` // binary/config/auth/log/other
	DetectedAt    LocalTime    `gorm:"column:detected_at;type:timestamp;not null;index:idx_fim_event_detected_at" json:"detected_at"`
	Status        string       `gorm:"column:status;type:varchar(20);default:'pending';index:idx_fim_event_status" json:"status"` // pending/confirmed/escalated
	ConfirmedBy   string       `gorm:"column:confirmed_by;type:varchar(100)" json:"confirmed_by"`
	ConfirmedAt   *LocalTime   `gorm:"column:confirmed_at;type:timestamp" json:"confirmed_at"`
	ConfirmReason string       `gorm:"column:confirm_reason;type:text" json:"confirm_reason"`
	AlertID       *uint        `gorm:"column:alert_id;type:int unsigned" json:"alert_id"`
	CreatedAt     LocalTime    `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (FIMEvent) TableName() string {
	return "fim_events"
}
