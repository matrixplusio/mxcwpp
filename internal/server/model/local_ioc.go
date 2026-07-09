package model

// LocalIOC 自有威胁情报(独立于外部 feed 同步):
// 来源=真实威胁研判自动提取 / 人工录入。持久化,每次同步重新灌入 Redis 参与 agent 匹配。
type LocalIOC struct {
	TenantID    string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IOCType     string    `gorm:"column:ioc_type;type:varchar(16);not null;index" json:"ioc_type"`      // ip / domain / hash / url
	Value       string    `gorm:"column:value;type:varchar(512);not null" json:"value"`                 // 与 ioc_type 组合唯一
	Source      string    `gorm:"column:source;type:varchar(24);not null;default:manual" json:"source"` // tp_extract / manual
	Severity    string    `gorm:"column:severity;type:varchar(16);default:high" json:"severity"`
	Description string    `gorm:"column:description;type:varchar(500)" json:"description"`
	RefType     string    `gorm:"column:ref_type;type:varchar(24)" json:"ref_type"` // alert(来源告警)
	RefID       string    `gorm:"column:ref_id;type:varchar(64)" json:"ref_id"`
	Enabled     bool      `gorm:"column:enabled;default:true;index" json:"enabled"`
	CreatedBy   string    `gorm:"column:created_by;type:varchar(64)" json:"created_by"`
	CreatedAt   LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (LocalIOC) TableName() string {
	return "local_iocs"
}
