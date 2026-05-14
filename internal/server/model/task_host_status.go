// Package model 定义数据模型
package model

import (
	"time"
)

// TaskHostStatus 任务主机执行状态
type TaskHostStatus struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	TaskID   string `gorm:"type:varchar(64);not null;index:idx_task_host,priority:1" json:"task_id"`
	HostID   string `gorm:"type:varchar(64);not null;index:idx_task_host,priority:2" json:"host_id"`
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
func (TaskHostStatus) TableName() string {
	return "task_host_status"
}

// TaskHostStatusDispatched 已下发
const TaskHostStatusDispatched = "dispatched"

// TaskHostStatusCompleted 已完成
const TaskHostStatusCompleted = "completed"

// TaskHostStatusTimeout 超时
const TaskHostStatusTimeout = "timeout"

// TaskHostStatusFailed 失败
const TaskHostStatusFailed = "failed"
