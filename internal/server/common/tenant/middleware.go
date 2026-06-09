package tenant

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Gin context key.
//
// JWT AuthMiddleware 解析 token 后调用 SetIdentity 注入；
// 业务 handler 通过 Get 取出。中间件链顺序：Auth → Tenant → Audit → 业务。
const (
	ginCtxIdentityKey = "tenant.identity"
)

// SetIdentity 把 Identity 写入 Gin context（兼容 c.MustGet / c.Get 风格）
// 并同时注入 request context（GORM 链路统一从 request context 读）。
func SetIdentity(c *gin.Context, id Identity) {
	c.Set(ginCtxIdentityKey, id)
	c.Request = c.Request.WithContext(WithContext(c.Request.Context(), id))
}

// GetIdentity 从 Gin context 取出 Identity。未注入返回零值。
func GetIdentity(c *gin.Context) Identity {
	if v, ok := c.Get(ginCtxIdentityKey); ok {
		if id, ok := v.(Identity); ok {
			return id
		}
	}
	// 兜底从 request context 取
	return FromContext(c.Request.Context())
}

// Middleware 业务路径强制租户身份的 Gin 中间件。
//
// 必须放在 AuthMiddleware 之后。AuthMiddleware 解析 JWT 后写入 Identity，
// 本中间件再次校验 Identity 非空。
//
// 规则：
//   - Identity 为空 → 401（鉴权链未正常注入）。
//   - 普通业务路径（默认行为）：
//     · TenantID 必须存在；
//     · 平台超管不允许走业务路径（即便 IsPlatformAdmin=true，
//     业务路径必须显式带 X-Tenant-ID 指明当前操作租户）。
//   - 平台路径（通过 AllowPlatformAdmin 选项）：
//     · IsPlatformAdmin=true 放行；
//     · 普通用户 403。
func Middleware() gin.HandlerFunc {
	return middlewareWith(false)
}

// AdminMiddleware 平台超管路径专用中间件。仅 IsPlatformAdmin=true 放行。
//
// 路径示例：/api/v2/admin/tenants / /api/v2/admin/system/health
func AdminMiddleware() gin.HandlerFunc {
	return middlewareWith(true)
}

func middlewareWith(adminPath bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := GetIdentity(c)

		if adminPath {
			if !id.IsPlatformAdmin {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"code":    "platform_admin_required",
					"message": "platform admin required",
				})
				return
			}
			c.Next()
			return
		}

		// 业务路径：必须有显式 tenant_id（即便平台超管也要带 X-Tenant-ID）
		if id.ID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    "missing_tenant",
				"message": "tenant_id missing in request context",
			})
			return
		}

		c.Next()
	}
}

// HeaderOverride 允许平台超管通过 X-Tenant-ID Header 指定当前操作的租户。
// 普通用户的 X-Tenant-ID Header 必须与 JWT claims 一致，否则 403（防穿越）。
//
// 该中间件应在 AuthMiddleware 之后、Middleware 之前调用。
func HeaderOverride() gin.HandlerFunc {
	return func(c *gin.Context) {
		hdr := c.GetHeader("X-Tenant-ID")
		if hdr == "" {
			c.Next()
			return
		}
		id := GetIdentity(c)
		if id.IsPlatformAdmin {
			id.ID = hdr
			SetIdentity(c, id)
			c.Next()
			return
		}
		if id.ID != hdr {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "cross_tenant_denied",
				"message": "X-Tenant-ID does not match token tenant",
			})
			return
		}
		c.Next()
	}
}
