// Package model 提供数据库模型定义
package model

// Port 端口资产模型
type Port struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Protocol    string    `gorm:"column:protocol;type:varchar(10);not null" json:"protocol"` // tcp/udp
	Port        int       `gorm:"column:port;type:int;not null" json:"port"`
	State       string    `gorm:"column:state;type:varchar(20)" json:"state"` // LISTEN/ESTABLISHED 等
	PID         string    `gorm:"column:pid;type:varchar(20)" json:"pid"`
	ProcessName string    `gorm:"column:process_name;type:varchar(255)" json:"process_name"`
	ContainerID string    `gorm:"column:container_id;type:varchar(64)" json:"container_id"`
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Port) TableName() string {
	return "ports"
}
