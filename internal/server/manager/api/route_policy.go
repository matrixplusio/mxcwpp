package api

import "strings"

// 路由分类：每条已注册的 Gin 路由必须落入下述某一类，供 CI 覆盖测试断言
// “不存在未分类路由”。新增路由若未在此登记 / 未映射到模块权限，测试即失败，
// 从而杜绝“注册了但没纳入访问控制策略”的空洞。
const (
	RouteClassPublic   = "public"              // 无需 JWT（登录、健康、下载、webhook 等）
	RouteClassInternal = "internal"            // 内部服务间调用，X-Internal-Secret 鉴权
	RouteClassPerm     = "authenticated-perm"  // JWT + RBAC 模块权限（EnforcePermissions）
	RouteClassBasic    = "authenticated-basic" // JWT 登录即可，非 RBAC 资源（如查询系统模式/改密）
	RouteClassAdmin    = "admin"               // JWT + 平台管理员（RoleMiddleware/AdminMiddleware）
	RouteClassUnknown  = "unclassified"        // 未纳入任何策略——CI 失败
)

func routeKey(method, path string) string { return method + " " + path }

// publicRoutes 是无需 JWT 的精确路由（method + path），避免用前缀误吞需鉴权的同前缀路由。
var publicRoutes = map[string]bool{
	"GET /health":                      true,
	"HEAD /health":                     true,
	"GET /health/ready":                true,
	"HEAD /health/ready":               true,
	"GET /metrics":                     true,
	"GET /agent/install.sh":            true,
	"GET /agent/uninstall.sh":          true,
	"GET /api/v1/health":               true,
	"GET /api/v1/system/version":       true,
	"GET /api/v1/system-config/site":   true, // 登录页需读站点名，公开；写走 admin
	"GET /api/v1/agent/update-check":   true,
	"GET /api/v1/auth/captcha":         true,
	"POST /api/v1/auth/login":          true,
	"POST /api/v1/auth/login-precheck": true,
	"POST /api/v1/auth/logout":         true, // 匿名幂等登出
}

// publicPrefixes 是无需 JWT 的下载 / 静态 / webhook 前缀（仅公开方法在此注册）。
var publicPrefixes = []string{
	"/uploads",
	"/api/v1/plugins/download",            // Agent 直连下载
	"/api/v1/agent/download",              // 安装脚本直连下载
	"/api/v1/dependency/download",         // Agent 直连下载
	"/api/v1/kube/audit-webhook",          // apiserver 经 cluster_token 鉴权
	"/api/v1/kube/scanner/report-webhook", // 集群内扫描器 token 鉴权
}

// basicRoutes 是登录即可访问（JWT，但非 RBAC 资源）的精确路由。
// 注意：/auth/me 由 handler 内部自校验 JWT，/auth/change-password 挂 AuthMiddleware，
// 二者不是 public——不能被 /api/v1/auth/ 前缀吞成公开。
var basicRoutes = map[string]bool{
	"GET /api/v1/auth/me":               true,
	"POST /api/v1/auth/change-password": true,
	"GET /api/v2/system/mode":           true,
}

// RouteCategory 判定一条已注册路由的访问控制分类。
// method 为 HTTP 方法，fullPath 为 Gin 注册路径（含 :param 占位符）。
func RouteCategory(method, fullPath string) string {
	key := routeKey(method, fullPath)

	// 登录即可（authenticated-basic）——精确匹配优先。
	if basicRoutes[key] {
		return RouteClassBasic
	}

	// v2 平台管理面（/admin、/config/change-requests、/mssp 均 admin 门禁）。
	if strings.HasPrefix(fullPath, "/api/v2/") {
		switch {
		case strings.HasPrefix(fullPath, "/api/v2/admin"),
			strings.HasPrefix(fullPath, "/api/v2/config/change-requests"),
			strings.HasPrefix(fullPath, "/api/v2/mssp"):
			return RouteClassAdmin
		}
		return RouteClassUnknown
	}

	// 内部服务路由
	if strings.HasPrefix(fullPath, "/api/v1/internal/") {
		return RouteClassInternal
	}

	// 公开路由（精确 + 下载/静态/webhook 前缀）
	if publicRoutes[key] || matchesPublicPrefix(fullPath) {
		return RouteClassPublic
	}

	// 其余 /api/v1 均为 JWT 认证路由，必须映射到模块权限（deny-by-default）。
	if strings.HasPrefix(fullPath, "/api/v1/") {
		if requiredPerm(method, fullPath) == permDenyUnclassified {
			return RouteClassUnknown
		}
		return RouteClassPerm
	}

	return RouteClassUnknown
}

// RoutePermission 返回 authenticated-perm 路由的模块权限码；非该类返回 ""。
// 供路由 manifest 记录“分类 = 具体 permission code”。
func RoutePermission(method, fullPath string) string {
	if RouteCategory(method, fullPath) != RouteClassPerm {
		return ""
	}
	return requiredPerm(method, fullPath)
}

func matchesPublicPrefix(fullPath string) bool {
	for _, p := range publicPrefixes {
		if fullPath == p || strings.HasPrefix(fullPath, p) {
			return true
		}
	}
	return false
}
