package service

import (
	"testing"
)

func TestMatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		actual     string
		constraint string
		expected   bool
	}{
		// >= 约束
		{">= 匹配", "9.3", ">=9", true},
		{">= 匹配边界", "9.0", ">=9", true},
		{">= 不匹配", "8.9", ">=9", false},
		{">= 匹配更高版本", "10.0", ">=9", true},
		// > 约束
		{"> 匹配", "9.1", ">9", true},
		{"> 不匹配边界", "9.0", ">9", false},
		{"> 不匹配", "8.9", ">9", false},
		// <= 约束
		{"<= 匹配", "7.9", "<=8", true},
		{"<= 匹配边界", "8.0", "<=8", true},
		{"<= 不匹配", "9.0", "<=8", false},
		// < 约束
		{"< 匹配", "7.9", "<8", true},
		{"< 不匹配边界", "8.0", "<8", false},
		{"< 不匹配", "9.0", "<8", false},
		// 精确匹配
		{"精确匹配", "9.3", "9.3", true},
		{"精确不匹配", "9.3", "9.4", false},
		// 空约束
		{"空约束", "9.3", "", true},
		// 多段版本号
		{"多段版本 >=", "9.3.2", ">=9", true},
		{"多段版本 >", "9.3.2", ">9.3", true},
		{"多段版本 <", "9.3.1", "<9.3.2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchVersion(tt.actual, tt.constraint)
			if result != tt.expected {
				t.Errorf("matchVersion(%q, %q) = %v, want %v", tt.actual, tt.constraint, result, tt.expected)
			}
		})
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int // -1: v1 < v2, 0: v1 == v2, 1: v1 > v2
	}{
		{"相等", "9.3", "9.3", 0},
		{"v1 小于 v2", "9.2", "9.3", -1},
		{"v1 大于 v2", "9.4", "9.3", 1},
		{"多段版本相等", "9.3.2", "9.3.2", 0},
		{"多段版本 v1 小于", "9.3.1", "9.3.2", -1},
		{"多段版本 v1 大于", "9.3.3", "9.3.2", 1},
		{"不同长度 v1 短", "9.3", "9.3.2", -1},
		{"不同长度 v1 长", "9.3.2", "9.3", 1},
		{"主版本不同", "10.0", "9.3", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersion(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareVersion(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}
