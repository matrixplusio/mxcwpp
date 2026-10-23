package tenant

import (
	"gorm.io/gorm"
)

// Apply 是 GORM Scope 函数。把当前 Identity 的 tenant_id 追加到查询 WHERE 中。
//
// 用法：
//
//	tn := tenant.FromContext(ctx)
//	db.Scopes(tn.Apply).Find(&hosts)
//
// 规则：
//   - Identity 为空（IsZero） → 拒绝查询（返回带 ErrMissingTenant 的 db 副本，
//     调用 .Find / .First 会立即 .Error 拿到错误，不会真正发出 SQL）。
//   - 平台超管（IsPlatformAdmin == true） → 不追加 WHERE，允许跨租户查询。
//     适用于 /api/v2/admin/* 等平台级路径。普通业务路径不应进入此分支。
//   - 普通租户 → 追加 WHERE tenant_id = ?。
//
// 注意：模型必须存在 tenant_id 列，否则 SQL 报"unknown column"。
// PR2a 阶段只有 User / Host 等少数 model 加了 tenant_id 列，其他 model 在
// 后续 PR2b 中逐步加列后再启用此 Scope。
func (i Identity) Apply(db *gorm.DB) *gorm.DB {
	if i.IsZero() {
		_ = db.AddError(ErrMissingTenant)
		return db
	}
	if i.IsPlatformAdmin {
		return db
	}
	return db.Where("tenant_id = ?", i.ID)
}

// MustApply 与 Apply 相同，但平台超管也强制带 tenant_id 过滤。
// 适用于"超管也应该走当前选中的租户视图"场景（前端切换 tenant 时）。
func (i Identity) MustApply(db *gorm.DB) *gorm.DB {
	if i.ID == "" {
		_ = db.AddError(ErrMissingTenant)
		return db
	}
	return db.Where("tenant_id = ?", i.ID)
}

// FilterByTenant 是 Apply 的命令式版本：直接返回追加 WHERE 后的 *gorm.DB。
// 用于不便走 Scopes 链式调用的场景（如 raw query / 复杂 join）。
func FilterByTenant(db *gorm.DB, id Identity) *gorm.DB {
	return id.Apply(db)
}
