package model

import (
	"time"
)

// FixTaskStatus 修复任务状态
type FixTaskStatus string

const (
	FixTaskStatusPending   FixTaskStatus = "pending"   // 待执行
	FixTaskStatusRunning   FixTaskStatus = "running"   // 执行中
	FixTaskStatusCompleted FixTaskStatus = "completed" // 已完成
	FixTaskStatusFailed    FixTaskStatus = "failed"    // 失败
)

// FixResultStatus 修复结果状态
type FixResultStatus string

const (
	FixResultStatusSuccess FixResultStatus = "success" // 成功
	FixResultStatusFailed  FixResultStatus = "failed"  // 失败
	FixResultStatusSkipped FixResultStatus = "skipped" // 跳过
)

// FixTaskHostStatus 修复任务主机执行状态
type FixTaskHostStatus struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	TaskID   string `gorm:"type:varchar(64);not null;index:idx_fix_task_host,priority:1" json:"task_id"`
	HostID   string `gorm:"type:varchar(64);not null;index:idx_fix_task_host,priority:2" json:"host_id"`
	Hostname string `gorm:"type:varchar(255)" json:"hostname"`
	// 冗余存储主机信息，避免主机删除后数据丢失
	IPAddress    string     `gorm:"type:varchar(255)" json:"ip_address"`                          // 主机 IP 地址（IPv4）
	BusinessLine string     `gorm:"type:varchar(255)" json:"business_line"`                       // 业务线
	OSFamily     string     `gorm:"type:varchar(50)" json:"os_family"`                            // OS 系列（如 rocky, ubuntu）
	OSVersion    string     `gorm:"type:varchar(50)" json:"os_version"`                           // OS 版本
	RuntimeType  string     `gorm:"type:varchar(20)" json:"runtime_type"`                         // 运行时类型（vm, docker, k8s）
	Status       string     `gorm:"type:varchar(20);not null;default:'dispatched'" json:"status"` // dispatched, completed, timeout, failed
	DispatchedAt *LocalTime `gorm:"type:datetime" json:"dispatched_at"`
	CompletedAt  *LocalTime `gorm:"type:datetime" json:"completed_at"`
	ErrorMessage string     `gorm:"type:text" json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// TableName 指定表名
func (FixTaskHostStatus) TableName() string {
	return "fix_task_host_status"
}

// FixTaskHostStatusDispatched 已下发
const FixTaskHostStatusDispatched = "dispatched"

// FixTaskHostStatusCompleted 已完成
const FixTaskHostStatusCompleted = "completed"

// FixTaskHostStatusTimeout 超时
const FixTaskHostStatusTimeout = "timeout"

// FixTaskHostStatusFailed 失败
const FixTaskHostStatusFailed = "failed"

// FixTask 修复任务模型
type FixTask struct {
	TaskID       string        `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	HostIDs      StringArray   `gorm:"column:host_ids;type:json;not null" json:"host_ids"`
	RuleIDs      StringArray   `gorm:"column:rule_ids;type:json;not null" json:"rule_ids"`
	Severities   StringArray   `gorm:"column:severities;type:json" json:"severities"`
	Status       FixTaskStatus `gorm:"column:status;type:varchar(20);default:'pending'" json:"status"`
	TotalCount   int           `gorm:"column:total_count;type:int;default:0" json:"total_count"`
	SuccessCount int           `gorm:"column:success_count;type:int;default:0" json:"success_count"`
	FailedCount  int           `gorm:"column:failed_count;type:int;default:0" json:"failed_count"`
	Progress     int           `gorm:"column:progress;type:int;default:0" json:"progress"` // 进度百分比 0-100
	CreatedBy    string        `gorm:"column:created_by;type:varchar(64)" json:"created_by"`
	CreatedAt    LocalTime     `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	CompletedAt  *LocalTime    `gorm:"column:completed_at;type:timestamp" json:"completed_at"`
}

// TableName 指定表名
func (FixTask) TableName() string {
	return "fix_tasks"
}

// FixResult 修复结果模型
// 复合主键 (task_id, host_id, rule_id) — 一次修复任务中每台主机的每条规则只有一条结果
type FixResult struct {
	TaskID   string          `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	HostID   string          `gorm:"primaryKey;column:host_id;type:varchar(64);not null" json:"host_id"`
	RuleID   string          `gorm:"primaryKey;column:rule_id;type:varchar(64);not null" json:"rule_id"`
	Status   FixResultStatus `gorm:"column:status;type:varchar(20);not null" json:"status"`
	Command  string          `gorm:"column:command;type:text" json:"command"`
	Output   string          `gorm:"column:output;type:text" json:"output"`
	ErrorMsg string          `gorm:"column:error_msg;type:text" json:"error_msg"`
	Message  string          `gorm:"column:message;type:varchar(500)" json:"message"`
	FixedAt  LocalTime       `gorm:"column:fixed_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"fixed_at"`
}

// TableName 指定表名
func (FixResult) TableName() string {
	return "fix_results"
}
