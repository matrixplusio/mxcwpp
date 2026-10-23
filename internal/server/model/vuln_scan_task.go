package model

import (
	"gorm.io/datatypes"
)

// VulnScanTask 漏洞扫描任务记录（targeted scan 异步任务）
//
// scope=global    → 全量扫，复用 ScanAll/ScanIncremental，target_host_ids 为空
// scope=hosts     → 指定 host_ids
// scope=business_line → 按业务线扫，business_line 字段记原始值，target_host_ids 存解析后
type VulnScanTask struct {
	TenantID        string         `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID              uint           `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	TaskID          string         `gorm:"column:task_id;type:varchar(64);not null;uniqueIndex" json:"taskId"`
	Scope           string         `gorm:"column:scope;type:varchar(20);not null" json:"scope"`
	TargetHostIDs   datatypes.JSON `gorm:"column:target_host_ids;type:json" json:"targetHostIds"`
	BusinessLine    string         `gorm:"column:business_line;type:varchar(100)" json:"businessLine,omitempty"`
	SyncDB          bool           `gorm:"column:sync_db;default:false" json:"syncDb"`
	ReconcileStale  bool           `gorm:"column:reconcile_stale;default:true" json:"reconcileStale"`
	Status          string         `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	ProgressTotal   int            `gorm:"column:progress_total;default:0" json:"progressTotal"`
	ProgressScanned int            `gorm:"column:progress_scanned;default:0" json:"progressScanned"`
	NewVulns        int            `gorm:"column:new_vulns;default:0" json:"newVulns"`
	PatchedCount    int            `gorm:"column:patched_count;default:0" json:"patchedCount"`
	VanishedCount   int            `gorm:"column:vanished_count;default:0" json:"vanishedCount"`
	ResurfacedCount int            `gorm:"column:resurfaced_count;default:0" json:"resurfacedCount"`
	ErrorMsg        string         `gorm:"column:error_msg;type:text" json:"errorMsg,omitempty"`
	TriggeredBy     string         `gorm:"column:triggered_by;type:varchar(50)" json:"triggeredBy"`
	StartedAt       *LocalTime     `gorm:"column:started_at;type:timestamp" json:"startedAt"`
	FinishedAt      *LocalTime     `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
	CreatedAt       LocalTime      `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"createdAt"`
}

// TableName 指定表名
func (VulnScanTask) TableName() string {
	return "vuln_scan_tasks"
}

// VulnScanTask 状态常量
const (
	ScanTaskStatusPending = "pending"
	ScanTaskStatusRunning = "running"
	ScanTaskStatusSuccess = "success"
	ScanTaskStatusFailed  = "failed"
)

// VulnScanTask scope 常量
const (
	ScanScopeGlobal       = "global"
	ScanScopeHosts        = "hosts"
	ScanScopeBusinessLine = "business_line"
)
