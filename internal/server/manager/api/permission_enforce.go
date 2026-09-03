package api

import (
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/audit"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PermissionResolver 让 role_permissions 表真正参与放行判定（纵向越权防护）。
//
// 缓存 role -> {permCode} 集合，避免每请求查库；UpdateRolePermissions 后调 Reload 失效刷新。
// admin 角色拥有全部权限，直接放行。
type PermissionResolver struct {
	db     *gorm.DB
	logger *zap.Logger
	mu     sync.RWMutex
	cache  map[string]map[string]bool // roleCode -> set(permCode)
	loaded bool
}

// globalResolver 供 RBAC 配置更新后失效刷新缓存（UpdateRolePermissions 调用）。
var globalResolver *PermissionResolver

// SetGlobalResolver 注册全局解析器（路由初始化时调用）。
func SetGlobalResolver(r *PermissionResolver) { globalResolver = r }

// ReloadGlobalResolver 刷新全局权限缓存；无解析器时安全空操作。
func ReloadGlobalResolver() {
	if globalResolver != nil {
		if err := globalResolver.Reload(); err != nil {
			globalResolver.logger.Warn("RBAC 权限缓存刷新失败", zap.Error(err))
		}
	}
}

// NewPermissionResolver 构造并立即加载一次缓存。
func NewPermissionResolver(db *gorm.DB, logger *zap.Logger) *PermissionResolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &PermissionResolver{db: db, logger: logger, cache: map[string]map[string]bool{}}
	if err := r.Reload(); err != nil {
		logger.Warn("RBAC 权限缓存初始加载失败，将按需懒加载", zap.Error(err))
	}
	return r
}

// Reload 从 role_permissions 全量重建缓存。
func (r *PermissionResolver) Reload() error {
	var rows []model.RolePermission
	if err := r.db.Find(&rows).Error; err != nil {
		return err
	}
	next := make(map[string]map[string]bool, 8)
	for _, rp := range rows {
		set := next[rp.RoleCode]
		if set == nil {
			set = map[string]bool{}
			next[rp.RoleCode] = set
		}
		set[rp.PermCode] = true
	}
	r.mu.Lock()
	r.cache = next
	r.loaded = true
	r.mu.Unlock()
	return nil
}

// Has 判断角色是否拥有某权限 code。admin 恒为 true。
func (r *PermissionResolver) Has(role, code string) bool {
	if role == string(model.UserRoleAdmin) {
		return true
	}
	r.mu.RLock()
	loaded := r.loaded
	set := r.cache[role]
	r.mu.RUnlock()
	if !loaded {
		if err := r.Reload(); err == nil {
			r.mu.RLock()
			set = r.cache[role]
			r.mu.RUnlock()
		}
	}
	return set[code]
}

// permDenyUnclassified 是 deny-by-default 哨兵：requiredPerm 对任何未登记的
// JWT 认证路由返回它。EnforcePermissions 见此值即拒绝非 admin（fail-closed），
// 而不是像旧实现那样返回空串放行。CI 路由覆盖测试断言不存在返回该哨兵的已注册路由。
const permDenyUnclassified = "__deny_unclassified__"

// modulePrefix 把路由按路径前缀映射到所属模块权限 code（最长前缀优先匹配）。
type modulePrefix struct {
	prefix string
	code   string
}

// modulePrefixes 是 apiV1Auth（含 apiV1Admin 子组）下每一条路由到所属模块的
// 权威映射。deny-by-default 要求这里覆盖全部认证路由——任何遗漏的前缀会被
// requiredPerm 判为未分类而对非 admin 拒绝，并由 route_policy CI 测试暴露。
//
// 更具体的前缀（如 /hosts/isolate）排在更泛的（/hosts）之前由排序保证。
var modulePrefixes = func() []modulePrefix {
	ps := []modulePrefix{
		// —— 漏洞管理 vuln ——
		{"/api/v1/vulnerabilities", "vuln"},
		{"/api/v1/host-vulnerabilities", "vuln"},
		{"/api/v1/remediation-tasks", "vuln"},
		{"/api/v1/remediation-policies", "vuln"},
		{"/api/v1/advisory", "vuln"},
		{"/api/v1/vuln-data-sources", "vuln"},
		{"/api/v1/vuln-bulletins", "vuln"},
		{"/api/v1/images", "vuln"},
		{"/api/v1/sbom", "vuln"},
		{"/api/v1/vex", "vuln"},
		// —— 容器集群 kube ——
		{"/api/v1/kube", "kube"},
		// —— 威胁检测 detection ——
		{"/api/v1/detection-rules", "detection"},
		{"/api/v1/threat-intel", "detection"},
		{"/api/v1/hunting", "detection"},
		{"/api/v1/edr", "detection"},
		{"/api/v1/bde", "detection"},
		{"/api/v1/ad-audit", "detection"},
		// —— 文件完整性 fim ——
		{"/api/v1/fim", "fim"},
		// —— 病毒查杀 virus ——
		{"/api/v1/antivirus", "virus"},
		{"/api/v1/quarantine", "virus"},
		{"/api/v1/rootkit", "virus"},
		{"/api/v1/memory-threats", "virus"},
		// —— 基线安全 baseline ——
		{"/api/v1/policies", "baseline"},
		{"/api/v1/policy-groups", "baseline"},
		{"/api/v1/rules", "baseline"},
		{"/api/v1/tasks", "baseline"},
		{"/api/v1/results", "baseline"},
		{"/api/v1/fix", "baseline"},
		{"/api/v1/fix-tasks", "baseline"},
		// —— 运维中心 operations（含危险主机动作与运维管理面）——
		{"/api/v1/network-block", "operations"},
		{"/api/v1/hosts/isolate", "operations"},
		{"/api/v1/hosts/release", "operations"},
		{"/api/v1/hosts/restart-agent", "operations"},
		{"/api/v1/hosts/dependency", "operations"},
		{"/api/v1/honeypot", "operations"},
		{"/api/v1/v2/honeypot", "operations"},
		{"/api/v1/reports", "operations"},
		{"/api/v1/inspection", "operations"},
		{"/api/v1/components", "operations"},
		{"/api/v1/packages", "operations"}, // 组件包删除（/components/.../packages 的独立删除端点）
		{"/api/v1/system/backups", "operations"},
		{"/api/v1/system/backup-config", "operations"},
		{"/api/v1/system/migration", "operations"},
		// —— 资产中心 assets ——
		{"/api/v1/hosts", "assets"},
		{"/api/v1/assets", "assets"},
		{"/api/v1/business-lines", "assets"},
		// —— 告警中心 alerts（含事件/攻击链/异常）——
		{"/api/v1/alerts", "alerts"},
		// 值班表属事件运营的一部分，与事件同权限域：能处置事件的人才该改排班。
		{"/api/v1/oncall", "alerts"},
		// 处置审批属处置权限域：能执行处置的人才该审批处置。
		{"/api/v1/response-actions", "alerts"},
		{"/api/v1/incidents", "alerts"},
		{"/api/v1/storylines", "alerts"},
		{"/api/v1/anomalies", "alerts"},
		// —— 安全概览 dashboard（含态势大屏）——
		{"/api/v1/dashboard", "dashboard"},
		{"/api/v1/screen", "dashboard"},
		// —— 系统监控 monitoring（含 AC 服务发现查询）——
		{"/api/v1/monitor", "monitoring"},
		{"/api/v1/discovery", "monitoring"},
		// —— 审计日志 audit_log ——
		{"/api/v1/audit-logs", "audit_log"},
		// —— 用户管理 user_manage（含 RBAC 角色/权限）——
		{"/api/v1/users", "user_manage"},
		{"/api/v1/rbac", "user_manage"},
		// —— 系统设置 system_config ——
		{"/api/v1/system-config", "system_config"},
		{"/api/v1/notifications", "system_config"},
		{"/api/v1/feature-flags", "system_config"},
		{"/api/v1/retention-policies", "system_config"},
	}
	// 长前缀优先，保证 /hosts/isolate 先于 /hosts 命中。
	sort.Slice(ps, func(i, j int) bool { return len(ps[i].prefix) > len(ps[j].prefix) })
	return ps
}()

func matchModule(fullPath string) string {
	for _, mp := range modulePrefixes {
		if fullPath == mp.prefix || strings.HasPrefix(fullPath, mp.prefix+"/") {
			return mp.code
		}
	}
	return ""
}

// respondPathHints 命中即按「处置」动作鉴权（告警解决/忽略、主机隔离/解除、病毒隔离等）。
var respondPathHints = []string{"/resolve", "/ignore", "/isolate", "/release", "/quarantine", "/dispose"}

func isRespondPath(fullPath string) bool {
	for _, h := range respondPathHints {
		if strings.Contains(fullPath, h) {
			return true
		}
	}
	return false
}

// requiredPerm 返回该请求所需的 module:action 权限码。
// 未登记的认证路由返回 permDenyUnclassified 哨兵（deny-by-default），绝不放行。
//
//	读 (GET/HEAD/OPTIONS) → module:view
//	处置 (resolve/ignore/isolate/...) → module:respond（模块支持时）
//	其余写 → module:manage
func requiredPerm(method, fullPath string) string {
	module := matchModule(fullPath)
	if module == "" {
		return permDenyUnclassified
	}
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return model.Perm(module, model.ActionView)
	}
	if isRespondPath(fullPath) && model.ModuleHasAction(module, model.ActionRespond) {
		return model.Perm(module, model.ActionRespond)
	}
	return model.Perm(module, model.ActionManage)
}

// EnforcePermissions 挂在 apiV1Auth 组上：按「模块 × 动作」校验当前角色权限。
// 读→module:view，写→module:manage，处置→module:respond。
//
// deny-by-default：admin 走显式超管通路（拥有全部权限，是显式规则而非空映射巧合放行）；
// 其余角色对未登记路由一律拒绝并记审计，杜绝纵向越权。
func (r *PermissionResolver) EnforcePermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		roleStr, _ := role.(string)

		// admin 显式超管通路：所有平台管理行为均放行（含尚未登记的路由）。
		if roleStr == string(model.UserRoleAdmin) {
			c.Next()
			return
		}

		code := requiredPerm(c.Request.Method, c.FullPath())
		if code == permDenyUnclassified {
			r.logger.Error("拒绝未分类路由（deny-by-default，请在 route policy 登记该路由的模块）",
				zap.String("role", roleStr),
				zap.String("method", c.Request.Method),
				zap.String("path", c.FullPath()),
			)
			r.denyAccess(c, roleStr, "unclassified route")
			return
		}
		if !r.Has(roleStr, code) {
			r.logger.Warn("拒绝越权操作：角色缺少权限",
				zap.String("role", roleStr),
				zap.String("required_perm", code),
				zap.String("method", c.Request.Method),
				zap.String("path", c.FullPath()),
			)
			r.denyAccess(c, roleStr, "required_perm="+code)
			return
		}
		c.Next()
	}
}

// denyAccess 记录 access.denied 审计事件并返回 403。detail 不含敏感信息。
func (r *PermissionResolver) denyAccess(c *gin.Context, roleStr, detail string) {
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	audit.Record(c.Request.Context(), audit.Event{
		ActorType:  model.ActorTypeUser,
		Username:   usernameStr,
		Action:     "access.denied",
		Outcome:    model.OutcomeFailure,
		Path:       c.Request.URL.Path,
		IP:         c.ClientIP(),
		StatusCode: http.StatusForbidden,
		Detail:     "role=" + roleStr + " " + detail,
	})
	Forbidden(c, "无权限执行该操作")
	c.Abort()
}
