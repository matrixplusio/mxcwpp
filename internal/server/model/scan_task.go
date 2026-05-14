package model

import "database/sql/driver"

// TaskType 任务类型
type TaskType string

const (
	TaskTypeBaselineScan TaskType = "baseline_scan"
)

// TargetType 目标类型
type TargetType string

const (
	TargetTypeAll      TargetType = "all"
	TargetTypeHostIDs  TargetType = "host_ids"
	TargetTypeOSFamily TargetType = "os_family"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusCreated   TaskStatus = "created"   // 已创建，等待用户确认执行
	TaskStatusPending   TaskStatus = "pending"   // 待执行，等待调度器处理
	TaskStatusRunning   TaskStatus = "running"   // 执行中
	TaskStatusCompleted TaskStatus = "completed" // 已完成
	TaskStatusFailed    TaskStatus = "failed"    // 失败
	TaskStatusCancelled TaskStatus = "cancelled" // 已取消
)

// TargetConfig 目标配置（JSON 格式）
type TargetConfig struct {
	HostIDs     []string    `json:"host_ids,omitempty"`
	OSFamily    []string    `json:"os_family,omitempty"`
	RuntimeType RuntimeType `json:"runtime_type,omitempty"` // 运行时类型筛选：vm/docker/k8s
}

// Value 实现 driver.Valuer 接口
func (t TargetConfig) Value() (driver.Value, error) { return JSONValue(t) }

// Scan 实现 sql.Scanner 接口
func (t *TargetConfig) Scan(value any) error { return JSONScan(t, value) }

// ScanTask 扫描任务模型
type ScanTask struct {
	TaskID       string       `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	Name         string       `gorm:"column:name;type:varchar(255)" json:"name"`
	Type         TaskType     `gorm:"column:type;type:varchar(50);not null" json:"type"`
	TargetType   TargetType   `gorm:"column:target_type;type:varchar(20);not null" json:"target_type"`
	TargetConfig TargetConfig `gorm:"column:target_config;type:json" json:"target_config"`
	PolicyID     string       `gorm:"column:policy_id;type:varchar(64);index" json:"policy_id"` // 兼容旧数据
	PolicyIDs    StringArray  `gorm:"column:policy_ids;type:json" json:"policy_ids"`            // 新字段：支持多策略
	RuleIDs      StringArray  `gorm:"column:rule_ids;type:json" json:"rule_ids"`
	Status       TaskStatus   `gorm:"column:status;type:varchar(20);default:'created'" json:"status"`

	// 超时配置
	TimeoutMinutes int `gorm:"column:timeout_minutes;type:int;default:10" json:"timeout_minutes"` // 任务超时时间（分钟），默认 10 分钟

	// 执行统计
	DispatchedHostCount int `gorm:"column:dispatched_host_count;type:int;default:0" json:"dispatched_host_count"` // 已下发主机数
	CompletedHostCount  int `gorm:"column:completed_host_count;type:int;default:0" json:"completed_host_count"`   // 已完成主机数（收到结果的主机数）

	// 失败信息
	FailedReason string `gorm:"column:failed_reason;type:varchar(500)" json:"failed_reason"` // 失败原因

	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
	ExecutedAt  *LocalTime `gorm:"column:executed_at;type:timestamp" json:"executed_at"`
	CompletedAt *LocalTime `gorm:"column:completed_at;type:timestamp" json:"completed_at"`
}

// GetPolicyIDs 获取策略ID列表（兼容旧数据）
func (t *ScanTask) GetPolicyIDs() []string {
	if len(t.PolicyIDs) > 0 {
		return t.PolicyIDs
	}
	if t.PolicyID != "" {
		return []string{t.PolicyID}
	}
	return []string{}
}

// TableName 指定表名
func (ScanTask) TableName() string {
	return "scan_tasks"
}
