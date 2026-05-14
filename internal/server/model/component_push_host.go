// Package model 提供数据库模型定义
package model

// ComponentPushHostStatus 主机推送状态
type ComponentPushHostStatus string

const (
	ComponentPushHostStatusPending ComponentPushHostStatus = "pending" // 待推送
	ComponentPushHostStatusSuccess ComponentPushHostStatus = "success" // 推送成功
	ComponentPushHostStatusFailed  ComponentPushHostStatus = "failed"  // 推送失败
)

// ComponentPushHost 组件推送主机记录表
// 记录每个主机的推送详细状态
type ComponentPushHost struct {
	ID        uint                    `gorm:"primaryKey" json:"id"`
	RecordID  uint                    `gorm:"index;not null" json:"record_id"`       // 推送记录 ID
	HostID    string                  `gorm:"size:64;not null" json:"host_id"`       // 主机 ID
	Hostname  string                  `gorm:"size:255" json:"hostname"`              // 主机名（冗余字段）
	Status    ComponentPushHostStatus `gorm:"size:32;default:pending" json:"status"` // 推送状态
	Message   string                  `gorm:"type:text" json:"message"`              // 推送消息/错误信息
	PushedAt  *LocalTime              `json:"pushed_at,omitempty"`                   // 推送时间
	CreatedAt LocalTime               `json:"created_at"`                            // 创建时间
	UpdatedAt LocalTime               `json:"updated_at"`                            // 更新时间

	// 关联
	PushRecord *ComponentPushRecord `gorm:"foreignKey:RecordID" json:"push_record,omitempty"`
}

// TableName 返回表名
func (ComponentPushHost) TableName() string {
	return "component_push_hosts"
}
