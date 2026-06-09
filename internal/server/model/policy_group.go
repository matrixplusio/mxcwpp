package model

// PolicyGroup 策略组模型
type PolicyGroup struct {
	TenantID    string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          string    `gorm:"primaryKey;column:id;type:varchar(64);not null" json:"id"`
	Name        string    `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Description string    `gorm:"column:description;type:text" json:"description"`
	Icon        string    `gorm:"column:icon;type:varchar(100)" json:"icon"`              // 图标（可选）
	Color       string    `gorm:"column:color;type:varchar(20)" json:"color"`             // 颜色（可选）
	SortOrder   int       `gorm:"column:sort_order;type:int;default:0" json:"sort_order"` // 排序顺序
	Enabled     bool      `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`
	CreatedAt   LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`

	// 关联关系 - 策略组下的策略
	Policies []Policy `gorm:"foreignKey:GroupID;references:ID" json:"policies,omitempty"`
}

// TableName 指定表名
func (PolicyGroup) TableName() string {
	return "policy_groups"
}
