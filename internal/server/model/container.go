// Package model 提供数据库模型定义
package model

// Container 容器资产模型
type Container struct {
	ID            string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID        string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	ContainerID   string    `gorm:"column:container_id;type:varchar(128);not null" json:"container_id"`
	ContainerName string    `gorm:"column:container_name;type:varchar(255)" json:"container_name"`
	Image         string    `gorm:"column:image;type:varchar(255)" json:"image"`
	ImageID       string    `gorm:"column:image_id;type:varchar(128)" json:"image_id"`
	Runtime       string    `gorm:"column:runtime;type:varchar(50)" json:"runtime"` // docker、containerd
	Status        string    `gorm:"column:status;type:varchar(50)" json:"status"`   // running、stopped 等
	CreatedAt     string    `gorm:"column:created_at;type:varchar(50)" json:"created_at"`
	CollectedAt   LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Container) TableName() string {
	return "containers"
}
