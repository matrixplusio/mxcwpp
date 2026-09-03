package audit

import (
	"net/http"
	"sort"
	"strings"
)

// 语义动作映射：把「HTTP 方法 + 路由模板」翻译成稳定的语义动词。
//
// 路由模板取自 gin 的 c.FullPath()（含 :param 占位，如 /api/v1/rbac/roles/:role），
// 比裸路径更稳，不受具体 ID 影响。匹配优先级：精确动作 > 模块前缀通用动词。

// actionRule 把方法+路由前缀映射到语义动词。prefix 用前缀匹配（长前缀优先）。
type actionRule struct {
	method string // 空串匹配任意写方法
	prefix string
	verb   string
}

// actionRules 高价值安全操作的显式动词映射。
// 未命中者回落到「模块.通用动词」（见 fallbackVerb）。
var actionRules = func() []actionRule {
	rs := []actionRule{
		// RBAC / 用户 / 认证
		{http.MethodPost, "/api/v1/rbac/roles", "role.create"},
		{http.MethodDelete, "/api/v1/rbac/roles", "role.delete"},
		{http.MethodPut, "/api/v1/rbac/roles/:role/permissions", "role.update_perms"},
		{http.MethodPut, "/api/v1/rbac/roles", "role.update"},
		{http.MethodPost, "/api/v1/users", "user.create"},
		{http.MethodPut, "/api/v1/users", "user.update"},
		{http.MethodDelete, "/api/v1/users", "user.delete"},
		// 漏洞 / 修复
		{http.MethodPost, "/api/v1/vulnerabilities/scan", "vuln.scan"},
		{http.MethodPost, "/api/v1/remediation-tasks", "remediation.create"},
		// 主机处置
		{http.MethodPost, "/api/v1/hosts/isolate", "host.isolate"},
		{http.MethodPost, "/api/v1/hosts/release", "host.release"},
		{http.MethodPost, "/api/v1/hosts/restart-agent", "host.restart_agent"},
		// 告警处置
		{http.MethodPost, "/api/v1/alerts", "alert.create"},
		// 基线策略
		{http.MethodPost, "/api/v1/policies", "policy.create"},
		{http.MethodPut, "/api/v1/policies", "policy.update"},
		{http.MethodDelete, "/api/v1/policies", "policy.delete"},
		// 检测规则
		{http.MethodPost, "/api/v1/detection-rules", "rule.create"},
		{http.MethodPut, "/api/v1/detection-rules", "rule.update"},
		{http.MethodDelete, "/api/v1/detection-rules", "rule.delete"},
		// 系统配置
		{"", "/api/v1/system-config", "system_config.update"},
		{"", "/api/v1/feature-flags", "feature_flag.update"},
	}
	sort.SliceStable(rs, func(i, j int) bool { return len(rs[i].prefix) > len(rs[j].prefix) })
	return rs
}()

// 处置类动作的路径片段 → 动词后缀。
var respondVerbs = map[string]string{
	"resolve":    "resolve",
	"ignore":     "ignore",
	"isolate":    "isolate",
	"release":    "release",
	"quarantine": "quarantine",
	"dispose":    "dispose",
	"approve":    "approve",
	"reject":     "reject",
	"confirm":    "confirm",
}

// SemanticAction 返回该写请求的语义动词。
//
// fullPath 为 gin 路由模板（c.FullPath()）；resourceType 用于回落动词的模块名。
// 命中显式规则优先；否则按路径处置片段或方法生成「资源.动词」。
func SemanticAction(method, fullPath, resourceType string) string {
	for _, r := range actionRules {
		if r.method != "" && r.method != method {
			continue
		}
		if fullPath == r.prefix || strings.HasPrefix(fullPath, r.prefix+"/") {
			return r.verb
		}
	}
	// 处置片段：/.../:id/resolve → alert.resolve
	for seg, verb := range respondVerbs {
		if strings.Contains(fullPath, "/"+seg) {
			return resourceType + "." + verb
		}
	}
	return resourceType + "." + fallbackVerb(method)
}

// fallbackVerb 按 HTTP 方法给出通用动词。
func fallbackVerb(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// Outcome 按 HTTP 状态码推导审计结果，供 HTTP 中间件使用。
func Outcome(status int) string { return statusToOutcome(status) }
