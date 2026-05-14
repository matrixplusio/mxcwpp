// Package engine 提供基线检查引擎的数据模型
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Policy 是策略集
type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	OSFamily    []string `json:"os_family"`
	OSVersion   string   `json:"os_version"`
	Enabled     bool     `json:"enabled"`
	Rules       []*Rule  `json:"rules"`
}

// Rule 是规则
type Rule struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	OSFamily    []string `json:"os_family,omitempty"`  // 可选：覆盖策略集的 OS 限制
	OSVersion   string   `json:"os_version,omitempty"` // 可选：覆盖策略集的版本限制
	Check       *Check   `json:"check"`
	Fix         *Fix     `json:"fix"`
}

// Check 是检查项
type Check struct {
	Condition string       `json:"condition"` // all/any/none
	Rules     []*CheckRule `json:"rules"`
}

// CheckRule 是单个检查规则
type CheckRule struct {
	Type   string   `json:"type"`
	Param  []string `json:"param"`
	Result string   `json:"result,omitempty"` // 用于 file_line_match 等需要特殊处理的检查
}

// Fix 是修复建议
type Fix struct {
	Suggestion      string   `json:"suggestion"`
	Command         string   `json:"command,omitempty"`
	RestartServices []string `json:"restart_services,omitempty"` // 修复后需重启的服务
}

// Result 是检查结果
type Result struct {
	RuleID        string
	PolicyID      string
	Status        Status
	Severity      string
	Category      string
	Title         string
	Actual        string
	Expected      string
	FixSuggestion string
	CheckedAt     time.Time
}

// Status 是检查状态
type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusError Status = "error"
	StatusNA    Status = "na" // 不适用
)

// CheckResult 是检查器返回的结果
type CheckResult struct {
	Pass     bool
	Actual   string
	Expected string
}

// Checker 是检查器接口
type Checker interface {
	Check(ctx context.Context, rule *CheckRule) (*CheckResult, error)
}

// MatchOS 检查策略是否匹配指定的 OS
func (p *Policy) MatchOS(osFamily, osVersion string) bool {
	// 检查 OS Family
	familyMatched := false
	for _, family := range p.OSFamily {
		if strings.EqualFold(family, osFamily) {
			familyMatched = true
			break
		}
	}
	if !familyMatched {
		return false
	}

	// 检查 OS Version（简化实现，支持 >= 和基本比较）
	if p.OSVersion != "" {
		return matchVersion(osVersion, p.OSVersion)
	}

	return true
}

// matchVersion 匹配版本（简化实现）
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

// compareVersion 比较版本（简化实现，仅支持数字版本号）
func compareVersion(v1, v2 string) int {
	// 提取主版本号（简化处理）
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int
		if i < len(v1Parts) {
			fmt.Sscanf(v1Parts[i], "%d", &v1Num)
		}
		if i < len(v2Parts) {
			fmt.Sscanf(v2Parts[i], "%d", &v2Num)
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
