// Package plugin 提供插件版本管理功能
package plugin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version 表示语义化版本
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string // 预发布版本（如 "alpha.1", "beta.2"）
	Build string // 构建元数据（如 "20240101"）
}

// ParseVersion 解析版本字符串（支持语义化版本格式）
// 格式：MAJOR.MINOR.PATCH[-PRE][+BUILD]
// 示例：1.0.0, 1.2.3-alpha.1, 2.0.0-beta.2+20240101
func ParseVersion(v string) (*Version, error) {
	// 移除前缀 "v"（如果存在）
	v = strings.TrimPrefix(v, "v")

	// 分离构建元数据
	build := ""
	if idx := strings.Index(v, "+"); idx != -1 {
		build = v[idx+1:]
		v = v[:idx]
	}

	// 分离预发布版本
	pre := ""
	if idx := strings.Index(v, "-"); idx != -1 {
		pre = v[idx+1:]
		v = v[:idx]
	}

	// 解析主版本号
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid version format: %s", v)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return &Version{
		Major: major,
		Minor: minor,
		Patch: patch,
		Pre:   pre,
		Build: build,
	}, nil
}

// String 返回版本字符串
func (v *Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Compare 比较两个版本
// 返回值：
//
//	-1: v < other
//	 0: v == other
//	 1: v > other
func (v *Version) Compare(other *Version) int {
	// 比较主版本号
	if v.Major < other.Major {
		return -1
	}
	if v.Major > other.Major {
		return 1
	}

	// 比较次版本号
	if v.Minor < other.Minor {
		return -1
	}
	if v.Minor > other.Minor {
		return 1
	}

	// 比较补丁版本号
	if v.Patch < other.Patch {
		return -1
	}
	if v.Patch > other.Patch {
		return 1
	}

	// 比较预发布版本
	return comparePreRelease(v.Pre, other.Pre)
}

// comparePreRelease 比较预发布版本
// 规则：无预发布版本 > 有预发布版本
// 如果有预发布版本，按字母数字顺序比较
func comparePreRelease(pre1, pre2 string) int {
	if pre1 == "" && pre2 == "" {
		return 0
	}
	if pre1 == "" {
		return 1 // 无预发布版本 > 有预发布版本
	}
	if pre2 == "" {
		return -1 // 有预发布版本 < 无预发布版本
	}

	// 按字母数字顺序比较
	if pre1 < pre2 {
		return -1
	}
	if pre1 > pre2 {
		return 1
	}
	return 0
}

// LessThan 检查版本是否小于另一个版本
func (v *Version) LessThan(other *Version) bool {
	return v.Compare(other) < 0
}

// GreaterThan 检查版本是否大于另一个版本
func (v *Version) GreaterThan(other *Version) bool {
	return v.Compare(other) > 0
}

// Equal 检查版本是否相等
func (v *Version) Equal(other *Version) bool {
	return v.Compare(other) == 0
}

// IsValid 检查版本字符串是否有效
func IsValidVersion(v string) bool {
	// 简单的正则表达式验证
	pattern := `^v?(\d+)\.(\d+)\.(\d+)(-[\w\.-]+)?(\+[\w\.-]+)?$`
	matched, _ := regexp.MatchString(pattern, v)
	return matched
}

// NormalizeVersion 规范化版本字符串（移除前缀 "v"，统一格式）
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}
