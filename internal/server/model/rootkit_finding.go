// Package model — Rootkit / DKOM 检测发现表 (C2).
package model

// RootkitFinding 一次扫描发现的 rootkit 异常.
//
// Agent edr/rootkit/dkom_*.go 扫出隐藏 PID / module / port / preload / proc 不一致
// → 上报 → 落本表 → manager API 提供给 UI.
type RootkitFinding struct {
	TenantID    string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Hostname    string    `gorm:"column:hostname;type:varchar(128)" json:"hostname"`
	Kind        string    `gorm:"column:kind;type:varchar(32);not null;index" json:"kind"` // hidden_pid|hidden_module|hidden_port|preload_anomaly|proc_dir_mismatch
	Detail      string    `gorm:"column:detail;type:varchar(1024)" json:"detail"`
	PID         int       `gorm:"column:pid;type:int" json:"pid,omitempty"`
	ModuleName  string    `gorm:"column:module_name;type:varchar(128)" json:"module_name,omitempty"`
	Severity    string    `gorm:"column:severity;type:varchar(20);not null;default:'high';index" json:"severity"`
	Status      string    `gorm:"column:status;type:varchar(20);not null;default:'open';index" json:"status"` // open|resolved
	ResolvedBy  string    `gorm:"column:resolved_by;type:varchar(100)" json:"resolved_by,omitempty"`
	ResolveNote string    `gorm:"column:resolve_note;type:varchar(512)" json:"resolve_note,omitempty"`
	DetectedAt  LocalTime `gorm:"column:detected_at;type:timestamp;not null;default:CURRENT_TIMESTAMP;index" json:"detected_at"`
	ResolvedAt  LocalTime `gorm:"column:resolved_at;type:timestamp;null;default:null" json:"resolved_at,omitempty"`
}

// TableName 表名.
func (RootkitFinding) TableName() string { return "rootkit_findings" }
