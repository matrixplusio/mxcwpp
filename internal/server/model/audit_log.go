// Package model 提供数据库模型定义
package model

// AuditLog 操作审计日志模型
type AuditLog struct {
	TenantID     string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Username     string    `gorm:"column:username;type:varchar(100);not null;index" json:"username"`
	Action       string    `gorm:"column:action;type:varchar(20);not null" json:"action"`                      // HTTP 方法：POST/PUT/DELETE
	ResourceType string    `gorm:"column:resource_type;type:varchar(100);not null;index" json:"resource_type"` // 资源类型，如 hosts/policies/rules
	ResourceID   string    `gorm:"column:resource_id;type:varchar(100)" json:"resource_id"`                    // 资源 ID
	Path         string    `gorm:"column:path;type:varchar(255);not null" json:"path"`                         // 请求路径
	IP           string    `gorm:"column:ip;type:varchar(50)" json:"ip"`                                       // 操作 IP
	Detail       string    `gorm:"column:detail;type:text" json:"detail"`                                      // 操作详情
	StatusCode   int       `gorm:"column:status_code;type:int" json:"status_code"`                             // HTTP 响应码
	CreatedAt    LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"created_at"`
}

// TableName 指定表名
func (AuditLog) TableName() string {
	return "audit_logs"
}
