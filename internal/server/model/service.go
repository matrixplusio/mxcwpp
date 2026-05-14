// Package model 提供数据库模型定义
package model

// Service 系统服务资产模型（注意：与 Service 服务模型区分开，这里指 systemd 服务）
type Service struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	ServiceName string    `gorm:"column:service_name;type:varchar(255);not null" json:"service_name"`
	ServiceType string    `gorm:"column:service_type;type:varchar(50)" json:"service_type"` // systemd、sysv
	Status      string    `gorm:"column:status;type:varchar(50)" json:"status"`             // active、inactive、failed 等
	Enabled     bool      `gorm:"column:enabled;type:boolean;default:false" json:"enabled"` // 是否开机自启
	Description string    `gorm:"column:description;type:text" json:"description"`
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Service) TableName() string {
	return "services"
}
