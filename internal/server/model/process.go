// Package model 提供数据库模型定义
package model

// Process 进程资产模型
type Process struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	PID         string    `gorm:"column:pid;type:varchar(20);not null" json:"pid"`
	PPID        string    `gorm:"column:ppid;type:varchar(20)" json:"ppid"`
	Cmdline     string    `gorm:"column:cmdline;type:text" json:"cmdline"`
	Exe         string    `gorm:"column:exe;type:varchar(512)" json:"exe"`
	ExeHash     string    `gorm:"column:exe_hash;type:varchar(64)" json:"exe_hash"`
	ContainerID string    `gorm:"column:container_id;type:varchar(64)" json:"container_id"`
	UID         string    `gorm:"column:uid;type:varchar(20)" json:"uid"`
	GID         string    `gorm:"column:gid;type:varchar(20)" json:"gid"`
	Username    string    `gorm:"column:username;type:varchar(100)" json:"username"`
	Groupname   string    `gorm:"column:groupname;type:varchar(100)" json:"groupname"`
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Process) TableName() string {
	return "processes"
}
