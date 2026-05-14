package celengine

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// LoadRulesFromDB 从数据库加载所有启用的检测规则
// 只加载 enabled=true 的规则，按 ID 排序保证确定性
func LoadRulesFromDB(db *gorm.DB) ([]model.DetectionRule, error) {
	var rules []model.DetectionRule
	err := db.Where("enabled = ?", true).Order("id ASC").Find(&rules).Error
	if err != nil {
		return nil, fmt.Errorf("查询 detection_rules 失败: %w", err)
	}
	return rules, nil
}

// LoadRuleByID 根据 ID 加载单条规则（用于调试或单规则热更新）
func LoadRuleByID(db *gorm.DB, id uint) (*model.DetectionRule, error) {
	var rule model.DetectionRule
	err := db.First(&rule, id).Error
	if err != nil {
		return nil, fmt.Errorf("查询 detection_rule id=%d 失败: %w", id, err)
	}
	return &rule, nil
}

// CountEnabledRules 统计启用的规则数量
func CountEnabledRules(db *gorm.DB) (int64, error) {
	var count int64
	err := db.Model(&model.DetectionRule{}).Where("enabled = ?", true).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("统计 detection_rules 失败: %w", err)
	}
	return count, nil
}
