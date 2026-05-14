// Package model 提供数据库模型定义
package model

// BusinessLine 业务线模型
type BusinessLine struct {
	ID          uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name        string    `gorm:"column:name;type:varchar(100);not null;uniqueIndex" json:"name"` // 业务线名称
	Code        string    `gorm:"column:code;type:varchar(50);not null;uniqueIndex" json:"code"`  // 业务线代码（唯一标识）
	Description string    `gorm:"column:description;type:text" json:"description"`                // 描述
	Owner       string    `gorm:"column:owner;type:varchar(100)" json:"owner"`                    // 负责人
	Contact     string    `gorm:"column:contact;type:varchar(200)" json:"contact"`                // 联系方式
	Enabled     bool      `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`        // 是否启用
	HostCount   int       `gorm:"-" json:"host_count"`                                            // 关联主机数量（不存储，查询时计算）
	CreatedAt   LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (BusinessLine) TableName() string {
	return "business_lines"
}
