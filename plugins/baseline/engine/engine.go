// Package engine 提供基线检查引擎
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Engine 是基线检查引擎
type Engine struct {
	logger   *zap.Logger
	checkers map[string]Checker // 检查器注册表
}

// NewEngine 创建新的检查引擎
func NewEngine(logger *zap.Logger) *Engine {
	engine := &Engine{
		logger:   logger,
		checkers: make(map[string]Checker),
	}

	// 注册内置检查器
	engine.RegisterChecker("file_kv", NewFileKVChecker(logger))
	engine.RegisterChecker("file_exists", NewFileExistsChecker(logger))
	engine.RegisterChecker("file_permission", NewFilePermissionChecker(logger))
	engine.RegisterChecker("file_line_match", NewFileLineMatchChecker(logger))
	engine.RegisterChecker("command_exec", NewCommandExecChecker(logger))
	engine.RegisterChecker("sysctl", NewSysctlChecker(logger))
	engine.RegisterChecker("service_status", NewServiceStatusChecker(logger))
	engine.RegisterChecker("file_owner", NewFileOwnerChecker(logger))
	engine.RegisterChecker("package_installed", NewPackageInstalledChecker(logger))

	return engine
}

// RegisterChecker 注册检查器
func (e *Engine) RegisterChecker(name string, checker Checker) {
	e.checkers[name] = checker
}

// Execute 执行基线检查
func (e *Engine) Execute(ctx context.Context, policies []*Policy, osFamily, osVersion string) []*Result {
	var results []*Result

	for _, policy := range policies {
		// OS 匹配
		if !policy.MatchOS(osFamily, osVersion) {
			e.logger.Debug("policy OS mismatch",
				zap.String("policy_id", policy.ID),
				zap.String("os_family", osFamily),
				zap.String("os_version", osVersion))
			continue
		}

		// 执行规则
		for _, rule := range policy.Rules {
			result := e.executeRule(ctx, policy, rule)
			if result != nil {
				results = append(results, result)
			}
		}
	}

	return results
}

// executeRule 执行单条规则
func (e *Engine) executeRule(ctx context.Context, policy *Policy, rule *Rule) *Result {
	result := &Result{
		RuleID:        rule.RuleID,
		PolicyID:      policy.ID,
		Severity:      rule.Severity,
		Category:      rule.Category,
		Title:         rule.Title,
		CheckedAt:     time.Now(),
		Status:        StatusPass,
		FixSuggestion: rule.Fix.Suggestion,
	}

	// 执行检查
	checkResult, err := e.executeCheck(ctx, rule.Check)
	if err != nil {
		result.Status = StatusError
		result.Actual = fmt.Sprintf("检查执行失败: %v", err)
		return result
	}

	// 根据检查结果设置状态
	if checkResult.Pass {
		result.Status = StatusPass
		result.Actual = checkResult.Actual
		result.Expected = checkResult.Expected
	} else {
		result.Status = StatusFail
		result.Actual = checkResult.Actual
		result.Expected = checkResult.Expected
	}

	return result
}

// executeCheck 执行检查项
func (e *Engine) executeCheck(ctx context.Context, check *Check) (*CheckResult, error) {
	// 处理条件组合
	switch check.Condition {
	case "all":
		// 所有子检查都通过才通过
		if len(check.Rules) == 0 {
			return nil, fmt.Errorf("no check rules defined")
		}
		var lastPassResult *CheckResult
		for _, subCheck := range check.Rules {
			result, err := e.executeSingleCheck(ctx, subCheck)
			if err != nil {
				// 配置错误（如未知检查类型）应该返回 error
				return nil, err
			}
			if !result.Pass {
				return result, nil
			}
			lastPassResult = result
		}
		// 所有检查都通过
		if lastPassResult != nil {
			return &CheckResult{
				Pass:     true,
				Actual:   fmt.Sprintf("所有 %d 项检查均通过", len(check.Rules)),
				Expected: lastPassResult.Expected,
			}, nil
		}
		return &CheckResult{Pass: true}, nil

	case "any":
		// 任一子检查通过即通过
		if len(check.Rules) == 0 {
			return nil, fmt.Errorf("no check rules defined")
		}
		var failedResults []string
		var expectedDescriptions []string
		var configErrors []string
		for _, subCheck := range check.Rules {
			result, err := e.executeSingleCheck(ctx, subCheck)
			if err != nil {
				// 记录配置错误，但继续检查其他规则
				configErrors = append(configErrors, err.Error())
				continue
			}
			if result.Pass {
				return result, nil
			}
			// 记录失败信息
			failedResults = append(failedResults, result.Actual)
			if result.Expected != "" {
				expectedDescriptions = append(expectedDescriptions, result.Expected)
			} else {
				expectedDescriptions = append(expectedDescriptions, e.describeCheckRule(subCheck))
			}
		}
		// 如果所有检查都是配置错误，返回 error
		if len(configErrors) == len(check.Rules) {
			return nil, fmt.Errorf("all checks failed with errors: %s", strings.Join(configErrors, "; "))
		}
		// 所有检查都失败，构建详细的失败信息
		actual := "所有备选检查项均未通过"
		if len(failedResults) > 0 && len(failedResults) <= 3 {
			actual = fmt.Sprintf("备选检查均未通过: %s", joinWithLimit(failedResults, "; ", 3))
		}
		expected := "满足以下任一条件"
		if len(expectedDescriptions) > 0 && len(expectedDescriptions) <= 3 {
			expected = fmt.Sprintf("满足以下任一条件: %s", joinWithLimit(expectedDescriptions, " 或 ", 3))
		}
		return &CheckResult{Pass: false, Actual: actual, Expected: expected}, nil

	case "none":
		// 所有子检查都不通过才通过
		if len(check.Rules) == 0 {
			return nil, fmt.Errorf("no check rules defined")
		}
		var configErrors []string
		for _, subCheck := range check.Rules {
			result, err := e.executeSingleCheck(ctx, subCheck)
			if err != nil {
				configErrors = append(configErrors, err.Error())
				continue
			}
			if result.Pass {
				return &CheckResult{
					Pass:     false,
					Actual:   fmt.Sprintf("存在通过的检查项: %s", result.Actual),
					Expected: fmt.Sprintf("以下条件都不应满足: %s", e.describeCheckRule(subCheck)),
				}, nil
			}
		}
		// 如果所有检查都是配置错误，返回 error
		if len(configErrors) == len(check.Rules) {
			return nil, fmt.Errorf("all checks failed with errors: %s", strings.Join(configErrors, "; "))
		}
		return &CheckResult{
			Pass:     true,
			Actual:   fmt.Sprintf("所有 %d 项禁止条件均未触发", len(check.Rules)),
			Expected: "所有禁止条件不应满足",
		}, nil

	default:
		// 默认：单个检查
		if len(check.Rules) == 0 {
			return nil, fmt.Errorf("no check rules defined")
		}
		return e.executeSingleCheck(ctx, check.Rules[0])
	}
}

// describeCheckRule 生成检查规则的描述
func (e *Engine) describeCheckRule(rule *CheckRule) string {
	switch rule.Type {
	case "service_status":
		if len(rule.Param) >= 2 {
			return fmt.Sprintf("服务 %s 状态为 %s", rule.Param[0], rule.Param[1])
		}
	case "command_exec":
		if len(rule.Param) >= 2 {
			return fmt.Sprintf("命令输出匹配: %s", rule.Param[1])
		}
	case "file_kv":
		if len(rule.Param) >= 3 {
			return fmt.Sprintf("%s 中 %s=%s", rule.Param[0], rule.Param[1], rule.Param[2])
		}
	case "file_line_match":
		if len(rule.Param) >= 2 {
			return fmt.Sprintf("文件 %s 包含匹配行", rule.Param[0])
		}
	case "sysctl":
		if len(rule.Param) >= 2 {
			return fmt.Sprintf("%s=%s", rule.Param[0], rule.Param[1])
		}
	case "file_exists":
		if len(rule.Param) >= 1 {
			return fmt.Sprintf("文件存在: %s", rule.Param[0])
		}
	case "file_permission":
		if len(rule.Param) >= 2 {
			return fmt.Sprintf("文件 %s 权限 <= %s", rule.Param[0], rule.Param[1])
		}
	}
	return fmt.Sprintf("[%s] 检查", rule.Type)
}

// joinWithLimit 连接字符串数组，限制最大数量
func joinWithLimit(items []string, sep string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, sep)
	}
	return strings.Join(items[:limit], sep) + fmt.Sprintf(" ... (共 %d 项)", len(items))
}

// executeSingleCheck 执行单个检查
func (e *Engine) executeSingleCheck(ctx context.Context, checkRule *CheckRule) (*CheckResult, error) {
	checker, exists := e.checkers[checkRule.Type]
	if !exists {
		return nil, fmt.Errorf("unknown check type: %s", checkRule.Type)
	}

	return checker.Check(ctx, checkRule)
}
