package api

import (
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
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

// modulePrefix 把写路由按路径前缀映射到所属模块权限 code（最长前缀优先匹配）。
// 仅 14 个模块级 code 中实际涉及写操作的模块在此登记。
type modulePrefix struct {
	prefix string
	code   string
}

// writeModulePrefixes 覆盖 apiV1Auth 组下全部写操作所属模块。
// 更具体的前缀（如 /hosts/isolate）排在更泛的（/hosts）之前由排序保证。
var writeModulePrefixes = func() []modulePrefix {
	ps := []modulePrefix{
		{"/api/v1/vulnerabilities", "vuln"},
		{"/api/v1/remediation-tasks", "vuln"},
		{"/api/v1/remediation-policies", "vuln"},
		{"/api/v1/advisory", "vuln"},
		{"/api/v1/vuln-data-sources", "vuln"},
		{"/api/v1/images", "vuln"},
		{"/api/v1/kube", "kube"},
		{"/api/v1/detection-rules", "detection"},
		{"/api/v1/threat-intel", "detection"},
		{"/api/v1/hunting", "detection"},
		{"/api/v1/fim", "fim"},
		{"/api/v1/antivirus", "virus"},
		{"/api/v1/quarantine", "virus"},
		{"/api/v1/rootkit", "virus"},
		{"/api/v1/memory-threats", "virus"},
		{"/api/v1/policies", "baseline"},
		{"/api/v1/policy-groups", "baseline"},
		{"/api/v1/rules", "baseline"},
		{"/api/v1/network-block", "operations"},
		{"/api/v1/hosts/isolate", "operations"},
		{"/api/v1/hosts/release", "operations"},
		{"/api/v1/hosts/restart-agent", "operations"},
		{"/api/v1/hosts/dependency", "operations"},
		{"/api/v1/honeypot", "operations"},
		{"/api/v1/v2/honeypot", "operations"},
		{"/api/v1/reports", "operations"},
		{"/api/v1/hosts", "assets"},
		{"/api/v1/business-lines", "assets"},
		{"/api/v1/alerts", "alerts"},
		{"/api/v1/storylines", "alerts"},
		{"/api/v1/anomalies", "alerts"},
	}
	// 长前缀优先，保证 /hosts/isolate 先于 /hosts 命中。
	sort.Slice(ps, func(i, j int) bool { return len(ps[i].prefix) > len(ps[j].prefix) })
	return ps
}()

// requiredWriteCode 返回该请求路径所属模块的权限 code；非写操作或未登记模块返回 ""。
func requiredWriteCode(method, fullPath string) string {
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return ""
	}
	for _, mp := range writeModulePrefixes {
		if fullPath == mp.prefix || strings.HasPrefix(fullPath, mp.prefix+"/") {
			return mp.code
		}
	}
	return ""
}

// EnforceWritePermissions 是挂在 apiV1Auth 组上的中间件：
// 对写操作按所属模块校验当前角色是否拥有对应权限 code，缺失则 403。
// 读操作（GET/HEAD/OPTIONS）与未登记模块放行。admin 角色恒通过。
func (r *PermissionResolver) EnforceWritePermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		code := requiredWriteCode(c.Request.Method, c.FullPath())
		if code == "" {
			c.Next()
			return
		}
		role, _ := c.Get("role")
		roleStr, _ := role.(string)
		if !r.Has(roleStr, code) {
			r.logger.Warn("拒绝越权写操作：角色缺少模块权限",
				zap.String("role", roleStr),
				zap.String("required_perm", code),
				zap.String("method", c.Request.Method),
				zap.String("path", c.FullPath()),
			)
			Forbidden(c, "无权限执行该操作，需要模块权限: "+code)
			c.Abort()
			return
		}
		c.Next()
	}
}
