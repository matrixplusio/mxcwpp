// Package tenant 提供多租户上下文与 GORM 行级隔离支持。
//
// 设计文档：docs/multi-tenant.md
//
// 使用模式：
//
//	(1) 鉴权中间件解析 JWT claims，取出 tenant_id 和 is_platform_admin，
//	    调用 tenant.WithContext(ctx, tenant.Identity{ID: tid, IsPlatformAdmin: pa}) 注入。
//
//	(2) 业务代码取 tenant：t := tenant.FromContext(c.Request.Context()).
//
//	(3) GORM 查询用 Scope：db.Scopes(tenant.FromContext(ctx).Apply).Find(&hosts).
//	    Apply 会在 SQL 中追加 WHERE tenant_id = ?。
//
//	(4) 平台超管 (IsPlatformAdmin == true) 走 /api/v2/admin/* 路径时，
//	    Apply 不会限制 tenant_id；普通业务路径仍然必须有显式 tenant_id。
package tenant

import (
	"context"
	"errors"
)

// Identity 表示当前请求上下文中的租户身份。
type Identity struct {
	// ID 租户 ID。空字符串视为未注入（拒绝业务查询）。
	ID string

	// Type 租户类型（standalone / mssp_parent / mssp_child / internal）。
	Type string

	// IsPlatformAdmin 平台超管标识。仅用于 /api/v2/admin/* 路径。
	// 普通业务路径中即便 IsPlatformAdmin=true，也会要求显式 tenant_id（防止误穿越）。
	IsPlatformAdmin bool
}

// IsZero 判断是否为空身份（未注入）。
func (i Identity) IsZero() bool {
	return i.ID == "" && !i.IsPlatformAdmin
}

// ctxKey 是 context.Value 的私有 key 类型，防止与其他包冲突。
type ctxKey struct{}

var identityKey = ctxKey{}

// WithContext 把租户身份注入 context。
func WithContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// FromContext 从 context 取出租户身份。未注入时返回零值 Identity。
//
// 调用方应自行判断 IsZero() / ID == ""，对于业务路径 ID 为空必须拒绝。
func FromContext(ctx context.Context) Identity {
	if ctx == nil {
		return Identity{}
	}
	if v, ok := ctx.Value(identityKey).(Identity); ok {
		return v
	}
	return Identity{}
}

// ErrMissingTenant 标准错误：请求未携带租户身份且非平台超管路径。
var ErrMissingTenant = errors.New("tenant_id missing in request context")

// ErrCrossTenantDenied 标准错误：检测到跨租户访问（业务层校验）。
var ErrCrossTenantDenied = errors.New("cross-tenant access denied")
