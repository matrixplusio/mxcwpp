// Package model 提供数据库模型定义
package model

// Volume 磁盘资产模型
type Volume struct {
	ID            string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID        string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Device        string    `gorm:"column:device;type:varchar(100)" json:"device"`           // /dev/sda1
	MountPoint    string    `gorm:"column:mount_point;type:varchar(255)" json:"mount_point"` // /、/home 等
	FileSystem    string    `gorm:"column:file_system;type:varchar(50)" json:"file_system"`  // ext4、xfs 等
	TotalSize     int64     `gorm:"column:total_size;type:bigint" json:"total_size"`         // 总大小（字节）
	UsedSize      int64     `gorm:"column:used_size;type:bigint" json:"used_size"`           // 已用大小（字节）
	AvailableSize int64     `gorm:"column:available_size;type:bigint" json:"available_size"` // 可用大小（字节）
	UsagePercent  float64   `gorm:"column:usage_percent;type:double" json:"usage_percent"`   // 使用率（百分比）
	CollectedAt   LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Volume) TableName() string {
	return "volumes"
}
