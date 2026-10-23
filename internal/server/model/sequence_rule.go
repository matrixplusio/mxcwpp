// Package model 提供数据库模型定义
package model

import (
	"database/sql/driver"
	"encoding/json"
)

// SequenceStep 序列检测的单个步骤
type SequenceStep struct {
	Name       string `json:"name"`
	Expression string `json:"expression"` // CEL 表达式
	Order      int    `json:"order"`
}

// SequenceSteps 序列步骤数组类型，用于 JSON 字段
type SequenceSteps []SequenceStep

// Value 实现 driver.Valuer 接口
func (s SequenceSteps) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan 实现 sql.Scanner 接口
func (s *SequenceSteps) Scan(value interface{}) error {
	if value == nil {
		*s = SequenceSteps{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, s)
}

// SequenceRule 序列检测规则模型
// 用于 Consumer 端基于多步 CEL 表达式 + Redis 状态机的行为序列检测
type SequenceRule struct {
	TenantID    string        `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint          `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string        `gorm:"type:varchar(200);not null;uniqueIndex" json:"name"`
	Steps       SequenceSteps `gorm:"type:json;not null" json:"steps"`
	WindowSecs  int           `gorm:"column:window_secs;not null;default:300" json:"windowSecs"` // 窗口秒数
	Severity    string        `gorm:"type:varchar(20);not null;index" json:"severity"`
	MitreID     string        `gorm:"type:varchar(50)" json:"mitreId"`
	Category    string        `gorm:"type:varchar(100);index" json:"category"`
	Description string        `gorm:"type:text" json:"description"`
	Enabled     bool          `gorm:"default:true;index" json:"enabled"`
	Builtin     bool          `gorm:"default:false" json:"builtin"`
	CreatedAt   LocalTime     `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   LocalTime     `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (SequenceRule) TableName() string {
	return "sequence_rules"
}
