package tenant

import (
	"context"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// RegisterAutoInjectHook 注册 GORM BeforeCreate Hook,
// 在 INSERT 时自动把 ctx 中的 tenant.Identity.ID 写入 model 的 tenant_id 字段。
//
// 用法（启动时一次性调用）:
//
//	if err := tenant.RegisterAutoInjectHook(db); err != nil { ... }
//
// 然后业务代码:
//
//	host := model.Host{HostID: "h-1", Hostname: "x"}
//	h.db.WithContext(c.Request.Context()).Create(&host) // tenant_id 自动注入
//
// 规则:
//   - 仅在 model 结构体存在 `TenantID` 字段时生效
//   - 仅当 ctx 含 Identity 且 Identity.ID 非空时注入
//   - 如果调用方已显式赋值 TenantID (非空字符串),不会覆盖
//   - 找不到 ctx Identity 时不注入 (兼容 INSERT 走系统级路径)
//
// 该 Hook 是 PR2d 的核心安全机制:即便业务 handler 漏写 TenantID 赋值,
// 也能保证 INSERT 的行带正确的 tenant_id。
func RegisterAutoInjectHook(db *gorm.DB) error {
	return db.Callback().Create().Before("gorm:before_create").
		Register("tenant:auto_inject", autoInjectTenantID)
}

func autoInjectTenantID(db *gorm.DB) {
	if db.Statement == nil || db.Statement.Schema == nil {
		return
	}
	field := db.Statement.Schema.LookUpField("TenantID")
	if field == nil {
		return // 该 model 不参与多租户隔离 (如 Tenant 本身 / Permission)
	}

	id := identityFromCtx(db.Statement.Context)
	if id.ID == "" {
		return // ctx 无 Identity,不注入 (系统路径)
	}

	rv := db.Statement.ReflectValue
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			setIfEmpty(db.Statement.Context, field, rv.Index(i), id.ID)
		}
	case reflect.Struct:
		setIfEmpty(db.Statement.Context, field, rv, id.ID)
	}
}

// setIfEmpty 仅在字段当前值为空字符串时才设置 tenant_id。
// 调用方显式给 TenantID 赋值的场景不会被覆盖。
func setIfEmpty(ctx context.Context, field *schema.Field, rv reflect.Value, tenantID string) {
	cur, isZero := field.ValueOf(ctx, rv)
	if !isZero {
		if s, ok := cur.(string); ok && s != "" {
			return
		}
	}
	_ = field.Set(ctx, rv, tenantID)
}

// identityFromCtx 从 GORM Statement.Context 取出 Identity。
// 兼容直接 WithContext 与中间件注入两种方式。
func identityFromCtx(ctx context.Context) Identity {
	if ctx == nil {
		return Identity{}
	}
	return FromContext(ctx)
}
