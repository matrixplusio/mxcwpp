// Package model 提供数据库模型定义
package model

// ComponentPushStatus 组件推送状态
type ComponentPushStatus string

const (
	ComponentPushStatusPending   ComponentPushStatus = "pending"   // 待推送
	ComponentPushStatusPushing   ComponentPushStatus = "pushing"   // 推送中
	ComponentPushStatusSuccess   ComponentPushStatus = "success"   // 推送成功
	ComponentPushStatusFailed    ComponentPushStatus = "failed"    // 推送失败
	ComponentPushStatusCancelled ComponentPushStatus = "cancelled" // 已取消
)

// ComponentPushRecord 组件推送记录表
// 记录每次推送更新的操作
type ComponentPushRecord struct {
	ID            uint                `gorm:"primaryKey" json:"id"`
	ComponentID   uint                `gorm:"index;not null" json:"component_id"`     // 组件 ID
	ComponentName string              `gorm:"size:64;not null" json:"component_name"` // 组件名称（冗余字段，方便查询）
	Version       string              `gorm:"size:32;not null" json:"version"`        // 推送的版本号
	TargetType    string              `gorm:"size:32;not null" json:"target_type"`    // 推送目标类型：all/selected
	TargetHosts   StringArray         `gorm:"type:json" json:"target_hosts"`          // 目标主机 ID 列表（如果 target_type=selected）
	Status        ComponentPushStatus `gorm:"size:32;default:pending" json:"status"`  // 推送状态
	TotalCount    int                 `gorm:"default:0" json:"total_count"`           // 总主机数
	SuccessCount  int                 `gorm:"default:0" json:"success_count"`         // 成功数
	FailedCount   int                 `gorm:"default:0" json:"failed_count"`          // 失败数
	FailedHosts   StringArray         `gorm:"type:json" json:"failed_hosts"`          // 失败的主机 ID 列表
	Force         bool                `gorm:"default:false" json:"force"`             // 是否强制更新（即使版本相同也更新）
	Message       string              `gorm:"type:text" json:"message"`               // 推送消息/备注
	CreatedBy     string              `gorm:"size:64" json:"created_by"`              // 创建者
	CreatedAt     LocalTime           `json:"created_at"`                             // 创建时间
	UpdatedAt     LocalTime           `json:"updated_at"`                             // 更新时间
	CompletedAt   *LocalTime          `json:"completed_at,omitempty"`                 // 完成时间

	// 关联
	Component *Component `gorm:"foreignKey:ComponentID" json:"component,omitempty"`
}

// 注意：ComponentPushRecord 不使用软删除，推送记录需要永久保存

// TableName 返回表名
func (ComponentPushRecord) TableName() string {
	return "component_push_records"
}

// ComponentPushProgress 组件推送进度（实时查询，不存储）
type ComponentPushProgress struct {
	RecordID      uint     `json:"record_id"`
	ComponentName string   `json:"component_name"`
	Version       string   `json:"version"`
	Status        string   `json:"status"`
	TotalCount    int      `json:"total_count"`
	SuccessCount  int      `json:"success_count"`
	FailedCount   int      `json:"failed_count"`
	Progress      float64  `json:"progress"` // 进度百分比 (0-100)
	FailedHosts   []string `json:"failed_hosts"`
	Message       string   `json:"message"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
	CompletedAt   string   `json:"completed_at,omitempty"`
}
