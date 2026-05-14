// Package service 提供策略和规则管理服务
package service

import (
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// PolicyService 是策略服务
type PolicyService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewPolicyService 创建策略服务实例
func NewPolicyService(db *gorm.DB, logger *zap.Logger) *PolicyService {
	return &PolicyService{
		db:     db,
		logger: logger,
	}
}

// GetPolicy 获取策略（包含规则）
func (s *PolicyService) GetPolicy(policyID string) (*model.Policy, error) {
	var policy model.Policy
	if err := s.db.Preload("Rules").First(&policy, "id = ?", policyID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("策略不存在: %s", policyID)
		}
		return nil, fmt.Errorf("查询策略失败: %w", err)
	}
	return &policy, nil
}

// ListPolicies 列出所有策略
func (s *PolicyService) ListPolicies(enabledOnly bool) ([]model.Policy, error) {
	var policies []model.Policy
	query := s.db
	if enabledOnly {
		query = query.Where("enabled = ?", true)
	}
	if err := query.Preload("Rules").Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("查询策略列表失败: %w", err)
	}
	return policies, nil
}

// CreatePolicy 创建策略
func (s *PolicyService) CreatePolicy(policy *model.Policy) error {
	if err := s.db.Create(policy).Error; err != nil {
		return fmt.Errorf("创建策略失败: %w", err)
	}
	s.logger.Info("策略已创建", zap.String("policy_id", policy.ID))
	return nil
}

// UpdatePolicy 更新策略
func (s *PolicyService) UpdatePolicy(policy *model.Policy) error {
	if err := s.db.Save(policy).Error; err != nil {
		return fmt.Errorf("更新策略失败: %w", err)
	}
	s.logger.Info("策略已更新", zap.String("policy_id", policy.ID))
	return nil
}

// DeletePolicy 删除策略（会级联删除规则）
func (s *PolicyService) DeletePolicy(policyID string) error {
	// 先删除关联的规则
	if err := s.db.Where("policy_id = ?", policyID).Delete(&model.Rule{}).Error; err != nil {
		return fmt.Errorf("删除规则失败: %w", err)
	}

	// 再删除策略
	if err := s.db.Delete(&model.Policy{}, "id = ?", policyID).Error; err != nil {
		return fmt.Errorf("删除策略失败: %w", err)
	}

	s.logger.Info("策略已删除", zap.String("policy_id", policyID))
	return nil
}

// GetRule 获取规则
func (s *PolicyService) GetRule(ruleID string) (*model.Rule, error) {
	var rule model.Rule
	if err := s.db.First(&rule, "rule_id = ?", ruleID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("规则不存在: %s", ruleID)
		}
		return nil, fmt.Errorf("查询规则失败: %w", err)
	}
	return &rule, nil
}

// ListRules 列出规则（可按策略过滤）
func (s *PolicyService) ListRules(policyID string) ([]model.Rule, error) {
	var rules []model.Rule
	query := s.db
	if policyID != "" {
		query = query.Where("policy_id = ?", policyID)
	}
	if err := query.Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("查询规则列表失败: %w", err)
	}
	return rules, nil
}

// CreateRule 创建规则
func (s *PolicyService) CreateRule(rule *model.Rule) error {
	if err := s.db.Create(rule).Error; err != nil {
		return fmt.Errorf("创建规则失败: %w", err)
	}
	s.logger.Info("规则已创建", zap.String("rule_id", rule.RuleID))
	return nil
}

// UpdateRule 更新规则
func (s *PolicyService) UpdateRule(rule *model.Rule) error {
	if err := s.db.Save(rule).Error; err != nil {
		return fmt.Errorf("更新规则失败: %w", err)
	}
	s.logger.Info("规则已更新", zap.String("rule_id", rule.RuleID))
	return nil
}

// DeleteRule 删除规则及其关联的检测结果
func (s *PolicyService) DeleteRule(ruleID string) error {
	// 先删除关联的检测结果
	if result := s.db.Where("rule_id = ?", ruleID).Delete(&model.ScanResult{}); result.Error != nil {
		s.logger.Warn("删除规则关联的检测结果失败", zap.String("rule_id", ruleID), zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		s.logger.Info("已清理规则关联的检测结果", zap.String("rule_id", ruleID), zap.Int64("count", result.RowsAffected))
	}

	// 删除规则
	if err := s.db.Delete(&model.Rule{}, "rule_id = ?", ruleID).Error; err != nil {
		return fmt.Errorf("删除规则失败: %w", err)
	}
	s.logger.Info("规则已删除", zap.String("rule_id", ruleID))
	return nil
}

// GetPoliciesForHost 根据主机信息获取适用的策略
func (s *PolicyService) GetPoliciesForHost(osFamily, osVersion string) ([]model.Policy, error) {
	return s.GetPoliciesForHostWithRuntime(osFamily, osVersion, "")
}

// GetPoliciesForHostWithRuntime 根据主机信息和运行时类型获取适用的策略
func (s *PolicyService) GetPoliciesForHostWithRuntime(osFamily, osVersion string, runtimeType model.RuntimeType) ([]model.Policy, error) {
	var policies []model.Policy

	// 查询启用的策略
	query := s.db.Where("enabled = ?", true)

	// 如果指定了 OS 系列，过滤匹配的策略
	// 支持 OS Family 兼容性：Rocky Linux 9 和 CentOS Stream 9 互相兼容
	if osFamily != "" {
		// 获取兼容的 OS Family 列表
		compatibleFamilies := getCompatibleOSFamilies(osFamily)

		// 构建 OR 查询条件
		var conditions []string
		var args []interface{}
		for _, family := range compatibleFamilies {
			conditions = append(conditions, "JSON_CONTAINS(os_family, ?)")
			args = append(args, fmt.Sprintf(`"%s"`, family))
		}

		if len(conditions) > 0 {
			query = query.Where(strings.Join(conditions, " OR "), args...)
		}
	}

	if err := query.Preload("Rules").Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("查询适用策略失败: %w", err)
	}

	// 过滤版本约束匹配的策略
	var matchedPolicies []model.Policy
	for _, policy := range policies {
		// 检查版本约束（优先使用 os_requirements，向后兼容 os_version）
		if osFamily != "" && osVersion != "" {
			if !matchOSRequirements(osFamily, osVersion, policy) {
				s.logger.Debug("策略版本约束不匹配",
					zap.String("policy_id", policy.ID),
					zap.String("host_os_family", osFamily),
					zap.String("host_os_version", osVersion))
				continue
			}
		}

		// 检查运行时类型匹配
		if runtimeType != "" && !policy.MatchesRuntimeType(runtimeType) {
			s.logger.Debug("策略不适用于当前运行时类型",
				zap.String("policy_id", policy.ID),
				zap.String("runtime_type", string(runtimeType)),
				zap.Strings("policy_runtime_types", policy.RuntimeTypes))
			continue
		}

		// 过滤规则中不适用的规则
		if runtimeType != "" {
			var filteredRules []model.Rule
			for _, rule := range policy.Rules {
				if rule.MatchesRuntimeType(runtimeType) && rule.Enabled {
					filteredRules = append(filteredRules, rule)
				} else {
					s.logger.Debug("规则不适用于当前运行时类型",
						zap.String("rule_id", rule.RuleID),
						zap.String("runtime_type", string(runtimeType)),
						zap.Strings("rule_runtime_types", rule.RuntimeTypes))
				}
			}
			policy.Rules = filteredRules
		}

		// 只有当策略有适用的规则时才添加
		if len(policy.Rules) > 0 {
			matchedPolicies = append(matchedPolicies, policy)
		}
	}

	s.logger.Debug("获取主机适用策略完成",
		zap.String("os_family", osFamily),
		zap.String("os_version", osVersion),
		zap.String("runtime_type", string(runtimeType)),
		zap.Int("matched_policies", len(matchedPolicies)))

	return matchedPolicies, nil
}

// matchVersion 匹配版本约束（参考 plugins/baseline/engine/models.go）
// 支持 >=、<=、>、< 和精确匹配
func matchVersion(actual, constraint string) bool {
	if constraint == "" {
		return true
	}

	// 支持 >= 前缀
	if strings.HasPrefix(constraint, ">=") {
		version := strings.TrimSpace(constraint[2:])
		return compareVersion(actual, version) >= 0
	}

	// 支持 > 前缀
	if strings.HasPrefix(constraint, ">") {
		version := strings.TrimSpace(constraint[1:])
		return compareVersion(actual, version) > 0
	}

	// 支持 <= 前缀
	if strings.HasPrefix(constraint, "<=") {
		version := strings.TrimSpace(constraint[2:])
		return compareVersion(actual, version) <= 0
	}

	// 支持 < 前缀
	if strings.HasPrefix(constraint, "<") {
		version := strings.TrimSpace(constraint[1:])
		return compareVersion(actual, version) < 0
	}

	// 精确匹配
	return actual == constraint
}

// compareVersion 比较版本号（参考 plugins/baseline/engine/models.go）
// 返回：-1 表示 v1 < v2，0 表示 v1 == v2，1 表示 v1 > v2
func compareVersion(v1, v2 string) int {
	// 分割版本号
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	// 逐段比较版本号
	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int
		if i < len(v1Parts) {
			v1Num, _ = strconv.Atoi(v1Parts[i])
		}
		if i < len(v2Parts) {
			v2Num, _ = strconv.Atoi(v2Parts[i])
		}

		if v1Num < v2Num {
			return -1
		}
		if v1Num > v2Num {
			return 1
		}
	}

	return 0
}

// getCompatibleOSFamilies 获取兼容的 OS Family 列表
// 例如：rocky 和 centos 在 EL9 上互相兼容
func getCompatibleOSFamilies(osFamily string) []string {
	// 定义 OS Family 兼容性映射
	compatibilityMap := map[string][]string{
		"rocky":  {"rocky", "centos", "rhel"}, // Rocky Linux 兼容 CentOS 和 RHEL
		"centos": {"centos", "rocky", "rhel"}, // CentOS 兼容 Rocky Linux 和 RHEL
		"rhel":   {"rhel", "rocky", "centos"}, // RHEL 兼容 Rocky Linux 和 CentOS
		"oracle": {"oracle", "rhel"},          // Oracle Linux 兼容 RHEL
	}

	// 如果有兼容性映射，返回兼容列表
	if compatible, ok := compatibilityMap[osFamily]; ok {
		return compatible
	}

	// 否则只返回自身
	return []string{osFamily}
}

// matchOSRequirements 检查主机是否满足策略的 OS 版本要求
// 优先使用 os_requirements，向后兼容 os_version
func matchOSRequirements(osFamily, osVersion string, policy model.Policy) bool {
	// 如果有详细的 os_requirements，使用它
	if len(policy.OSRequirements) > 0 {
		// 查找匹配的 OS Family 要求
		for _, req := range policy.OSRequirements {
			if req.OSFamily == osFamily {
				// 检查最小版本
				if req.MinVersion != "" {
					if compareVersion(osVersion, req.MinVersion) < 0 {
						return false
					}
				}
				// 检查最大版本
				if req.MaxVersion != "" {
					if compareVersion(osVersion, req.MaxVersion) > 0 {
						return false
					}
				}
				// 找到匹配的 OS Family 且版本满足要求
				return true
			}
		}
		// os_requirements 中没有该 OS Family，不匹配
		return false
	}

	// 向后兼容：使用旧的 os_version 字段
	if policy.OSVersion != "" {
		return matchVersion(osVersion, policy.OSVersion)
	}

	// 没有版本约束，匹配
	return true
}
