// Package model 提供数据库模型定义
package model

// DetectionRule CEL 检测规则模型
// 用于 Consumer 端基于 CEL 表达式对 Kafka 事件进行实时检测并生成告警
type DetectionRule struct {
	TenantID     string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint        `gorm:"primaryKey;autoIncrement" json:"id"`
	Name         string      `gorm:"type:varchar(200);not null;uniqueIndex" json:"name"`
	Expression   string      `gorm:"type:text;not null" json:"expression"` // CEL 表达式
	Severity     string      `gorm:"type:varchar(20);not null;index" json:"severity"`
	MitreID      string      `gorm:"type:varchar(50)" json:"mitreId"`
	Category     string      `gorm:"type:varchar(100);index" json:"category"`
	Description  string      `gorm:"type:text" json:"description"`
	DataTypes    StringArray `gorm:"type:json" json:"dataTypes"` // 适用的 DataType 列表（如 "3000", "3001"）
	Enabled      bool        `gorm:"default:true;index" json:"enabled"`
	Builtin      bool        `gorm:"default:false" json:"builtin"`
	UserModified bool        `gorm:"column:user_modified;default:false" json:"userModified"`
	CreatedAt    LocalTime   `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime   `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (DetectionRule) TableName() string {
	return "detection_rules"
}

// MatchesDataType 判断当前规则是否适用于指定 DataType
// DataTypes 为空时视为匹配任何 DataType
func (r *DetectionRule) MatchesDataType(dataType int32) bool {
	if len(r.DataTypes) == 0 {
		return true
	}
	target := itoa32(dataType)
	for _, dt := range r.DataTypes {
		if dt == target {
			return true
		}
	}
	return false
}

// itoa32 将 int32 转为字符串（避免在 model 包引入 strconv 的 package-level 依赖展开）
func itoa32(v int32) string {
	// 简单实现，避免引入额外依赖；若 v 为 0 直接返回
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
