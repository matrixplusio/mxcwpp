// Package model 提供数据库模型定义
package model

// App 应用资产模型
type App struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	AppType     string    `gorm:"column:app_type;type:varchar(50);not null" json:"app_type"` // mysql、redis、nginx、kafka 等
	AppName     string    `gorm:"column:app_name;type:varchar(255)" json:"app_name"`
	Version     string    `gorm:"column:version;type:varchar(100)" json:"version"`
	Port        int       `gorm:"column:port;type:int" json:"port"`
	ProcessID   string    `gorm:"column:process_id;type:varchar(20)" json:"process_id"`
	ConfigPath  string    `gorm:"column:config_path;type:varchar(512)" json:"config_path"`
	DataPath    string    `gorm:"column:data_path;type:varchar(512)" json:"data_path"`
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (App) TableName() string {
	return "apps"
}
