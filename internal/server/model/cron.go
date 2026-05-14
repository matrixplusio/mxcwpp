// Package model 提供数据库模型定义
package model

// Cron 定时任务资产模型
type Cron struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	User        string    `gorm:"column:user;type:varchar(100);not null" json:"user"`         // root、username
	Schedule    string    `gorm:"column:schedule;type:varchar(100);not null" json:"schedule"` // 调度表达式（* * * * *）
	Command     string    `gorm:"column:command;type:text;not null" json:"command"`           // 执行的命令
	CronType    string    `gorm:"column:cron_type;type:varchar(50)" json:"cron_type"`         // crontab、systemd-timer
	Enabled     bool      `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`    // 是否启用
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Cron) TableName() string {
	return "cron_jobs"
}
