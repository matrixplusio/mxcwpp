package tenant

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GinScope 是 gin handler 的便捷入口。
//
// 用法（业务 handler 内）：
//
//	if err := h.db.Model(&model.Host{}).Scopes(tenant.GinScope(c)).Find(&hosts).Error; err != nil { ... }
//
// 如果 gin context 中没有 Identity（鉴权链未正确注入），
// 返回一个会把 ErrMissingTenant 注入到 *gorm.DB 的 Scope；
// 后续 .Find / .First 等终结方法会立即得到错误，不会真的发出 SQL。
//
// 该函数等价于：
//
//	tenant.GetIdentity(c).Apply
//
// 提供 GinScope 是为了减少 handler 模板字符（每条查询少写一行）。
func GinScope(c *gin.Context) func(*gorm.DB) *gorm.DB {
	id := GetIdentity(c)
	return id.Apply
}

// GinScopeStrict 与 GinScope 相同，但即便 IsPlatformAdmin=true，
// 也会强制使用当前 Identity.ID 过滤。用于"平台超管也按当前选中的租户视图查询"。
func GinScopeStrict(c *gin.Context) func(*gorm.DB) *gorm.DB {
	id := GetIdentity(c)
	return id.MustApply
}

// MustGinIdentity 取出 Identity，断言非空 ID。
// 鉴权链已确保 ID 非空（Middleware()），但显式 must 让代码可读。
func MustGinIdentity(c *gin.Context) Identity {
	id := GetIdentity(c)
	if id.ID == "" {
		// 不 panic，仅返回零值；调用方应通过 Middleware 提前阻挡未注入的情况。
		return Identity{}
	}
	return id
}
