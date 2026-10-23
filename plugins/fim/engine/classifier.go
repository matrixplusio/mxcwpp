package engine

import (
	"strings"
)

// classificationRule 分类规则
type classificationRule struct {
	prefixes []string
	severity string
	category string
}

// classificationRules 分类规则表（按优先级排序）
var classificationRules = []classificationRule{
	{
		prefixes: []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"},
		severity: "critical",
		category: "binary",
	},
	{
		prefixes: []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/pam.d/"},
		severity: "high",
		category: "auth",
	},
	{
		prefixes: []string{"/etc/ssh/"},
		severity: "high",
		category: "ssh",
	},
	{
		prefixes: []string{"/etc/crontab", "/etc/cron.d/", "/etc/systemd/system/", "/etc/init.d/"},
		severity: "high",
		category: "config",
	},
	{
		prefixes: []string{"/etc/"},
		severity: "medium",
		category: "config",
	},
}

// Classify 为 FIMEvent 分配 severity 和 category
func Classify(event *FIMEvent) {
	event.Severity = "low"
	event.Category = "other"

	for _, rule := range classificationRules {
		if matchesAnyPrefix(event.FilePath, rule.prefixes) {
			event.Severity = rule.severity
			event.Category = rule.category
			break
		}
	}

	// added/removed 比 changed 提升一级 severity
	if event.ChangeType == "added" || event.ChangeType == "removed" {
		event.Severity = promoteSeverity(event.Severity)
	}
}

// matchesAnyPrefix 检查路径是否匹配任一前缀
func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}

// promoteSeverity 提升一级严重性
func promoteSeverity(severity string) string {
	switch severity {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return severity
	}
}
