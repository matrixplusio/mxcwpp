package model

// ConfigBackup 配置备份记录
type ConfigBackup struct {
	TenantID  string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name      string      `gorm:"column:name;type:varchar(100);not null" json:"name"`
	Type      string      `gorm:"column:type;type:varchar(20);not null;default:'manual'" json:"type"`
	Scope     StringArray `gorm:"column:scope;type:json" json:"scope"`
	FilePath  string      `gorm:"column:file_path;type:varchar(500)" json:"-"`
	FileSize  int64       `gorm:"column:file_size;type:bigint;default:0" json:"file_size"`
	Status    string      `gorm:"column:status;type:varchar(20);not null;default:'creating'" json:"status"`
	Remark    string      `gorm:"column:remark;type:varchar(500)" json:"remark"`
	CreatedAt LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (ConfigBackup) TableName() string {
	return "config_backups"
}
