// Package model 提供数据库模型定义
package model

// Kmod 内核模块资产模型
type Kmod struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	ModuleName  string    `gorm:"column:module_name;type:varchar(255);not null" json:"module_name"`
	Size        int64     `gorm:"column:size;type:bigint" json:"size"`        // 模块大小（字节）
	UsedBy      int       `gorm:"column:used_by;type:int" json:"used_by"`     // 引用计数
	State       string    `gorm:"column:state;type:varchar(50)" json:"state"` // Live、Loading、Unloading
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Kmod) TableName() string {
	return "kernel_modules"
}
