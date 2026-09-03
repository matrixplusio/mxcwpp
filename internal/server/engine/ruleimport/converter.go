// Package ruleimport 把 Falco / Sigma / Tetragon 规则转成 mxcwpp CEL 规则。
//
// 设计文档: docs/falco-sigma-integration.md
//
// 原则:
//   - 不强行 100% 兼容; 复杂规则人工 review 标 unsupported
//   - 转换后产物落入 detection_rules 表 + 标 source=falco/sigma/tetragon
//   - 升级时增量同步 (基于 source rule_id + version)
package ruleimport

import (
	"fmt"
	"strings"
)

// Source 是规则来源。
type Source string

const (
	SourceFalco    Source = "falco"
	SourceSigma    Source = "sigma"
	SourceTetragon Source = "tetragon"
)

// ConvertedRule 是转换后的规则,准备入 detection_rules 表。
type ConvertedRule struct {
	Source            Source
	SourceID          string // 源中的唯一 ID
	Name              string
	Severity          string // critical / high / medium / low
	CEL               string // 等价 CEL 表达式
	ATTCKTactic       string
	ATTCK             string
	Description       string
	Tags              []string
	Unsupported       bool
	UnsupportedReason string
}

// FalcoRule 是 Falco YAML 规则的最小 schema。
type FalcoRule struct {
	Rule      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
}

// SigmaRule 是 Sigma YAML 规则的最小 schema。
type SigmaRule struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Description string                 `yaml:"description"`
	Level       string                 `yaml:"level"`
	Tags        []string               `yaml:"tags"`
	Detection   map[string]interface{} `yaml:"detection"`
	LogSource   map[string]string      `yaml:"logsource"`
}

// ConvertFalco 把 Falco 规则转 ConvertedRule。
func ConvertFalco(r FalcoRule) ConvertedRule {
	out := ConvertedRule{
		Source:      SourceFalco,
		SourceID:    r.Rule,
		Name:        r.Rule,
		Severity:    mapFalcoPriority(r.Priority),
		Description: r.Desc,
		Tags:        r.Tags,
	}
	cel, ok := falcoConditionToCEL(r.Condition)
	if !ok {
		out.Unsupported = true
		out.UnsupportedReason = "falco condition contains unsupported operators (and / macro / list)"
		return out
	}
	out.CEL = cel
	out.ATTCK = extractATTCKFromTags(r.Tags)
	return out
}

// ConvertSigma 把 Sigma 规则转 ConvertedRule。
func ConvertSigma(r SigmaRule) ConvertedRule {
	out := ConvertedRule{
		Source:      SourceSigma,
		SourceID:    r.ID,
		Name:        r.Title,
		Severity:    mapSigmaLevel(r.Level),
		Description: r.Description,
		Tags:        r.Tags,
	}
	cel, ok := sigmaDetectionToCEL(r.Detection)
	if !ok {
		out.Unsupported = true
		out.UnsupportedReason = "sigma detection requires advanced selection logic"
		return out
	}
	out.CEL = cel
	out.ATTCK = extractATTCKFromTags(r.Tags)
	return out
}

// mapFalcoPriority Falco 优先级映射到 mxcwpp severity。
func mapFalcoPriority(p string) string {
	switch strings.ToLower(p) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "notice", "informational", "debug":
		return "low"
	default:
		return "medium"
	}
}

// mapSigmaLevel Sigma level 映射到 mxcwpp severity。
func mapSigmaLevel(l string) string {
	switch strings.ToLower(l) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "informational":
		return "low"
	default:
		return "medium"
	}
}

// falcoConditionToCEL 把 Falco condition 转 CEL。
//
// 当前简化实现:仅支持基本比较运算符;复杂宏/列表/管道走 unsupported。
func falcoConditionToCEL(cond string) (string, bool) {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return "", false
	}
	// 拒绝包含 macro/list 的 condition
	if strings.Contains(cond, "(") && (strings.Contains(cond, "and") || strings.Contains(cond, "in (")) {
		return "", false
	}
	// 简单等价替换
	cel := cond
	cel = strings.ReplaceAll(cel, " and ", " && ")
	cel = strings.ReplaceAll(cel, " or ", " || ")
	cel = strings.ReplaceAll(cel, " not ", " !")
	cel = strings.ReplaceAll(cel, "=", "==")
	return cel, true
}

// sigmaDetectionToCEL 把 Sigma detection 转 CEL。
//
// 仅支持 selection + condition 形式;复杂多 selection 走 unsupported。
func sigmaDetectionToCEL(detection map[string]interface{}) (string, bool) {
	if len(detection) == 0 {
		return "", false
	}
	condition, hasCond := detection["condition"]
	if hasCond {
		if s, ok := condition.(string); ok && s != "selection" {
			return "", false // 复杂 condition (and/or selection)
		}
	}
	sel, ok := detection["selection"]
	if !ok {
		return "", false
	}
	selMap, ok := sel.(map[string]interface{})
	if !ok {
		return "", false
	}

	var parts []string
	for k, v := range selMap {
		switch vv := v.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s == %q", k, vv))
		case int, int32, int64, float32, float64:
			parts = append(parts, fmt.Sprintf("%s == %v", k, vv))
		case []interface{}:
			// IN 列表: name in [...]
			items := make([]string, 0, len(vv))
			for _, it := range vv {
				items = append(items, fmt.Sprintf("%q", fmt.Sprint(it)))
			}
			parts = append(parts, fmt.Sprintf("%s in [%s]", k, strings.Join(items, ",")))
		default:
			return "", false
		}
	}
	return strings.Join(parts, " && "), true
}

// extractATTCKFromTags 从 tags 提取 ATT&CK ID (如 "attack.t1059")。
func extractATTCKFromTags(tags []string) string {
	for _, t := range tags {
		if strings.HasPrefix(t, "attack.t") {
			return strings.TrimPrefix(t, "attack.")
		}
	}
	return ""
}
