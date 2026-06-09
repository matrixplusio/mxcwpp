# 多租户工程接入指南（PR2c+）

> 配套设计文档：[multi-tenant.md](multi-tenant.md)
>
> 本文是**工程视角的接入手册**。说明每个 biz/api handler 如何安全引入 `tenant.Scope`，避免行级隔离漏洞。

---

## 1. 接入清单（按 PR 切片）

| PR | 范围 | 状态 |
|----|------|------|
| PR2a | Tenant model + JWT claims + Middleware + Identity | ✅ 已合 |
| PR2b | 91 业务 model 加 `tenant_id` 列 | ✅ 已合 |
| **PR2c**（本 PR） | Scope 框架 + GinScope helper + Hosts 接入 PoC（ListHosts / GetHost） + 跨租户单元测试 | 🚧 |
| PR2d | 全仓 biz handler 接入 Scope（按模块分批） + lint 规则防裸查询 + /api/v2/admin/* | 待开 |

---

## 2. 接入方式（强约束）

### 2.1 查询路径：必须走 `Scopes(tenant.GinScope(c))`

```go
// ❌ 错误（v1 残留写法，跨租户穿越）
var hosts []model.Host
h.db.Model(&model.Host{}).Find(&hosts)

// ✅ 正确
var hosts []model.Host
h.db.Model(&model.Host{}).Scopes(tenant.GinScope(c)).Find(&hosts)
```

### 2.2 单条查询：在 Where 之前接 Scope

```go
// ❌ 错误
h.db.Where("host_id = ?", id).First(&host)

// ✅ 正确（Scope 必须早于 Where 链式调用）
h.db.Scopes(tenant.GinScope(c)).Where("host_id = ?", id).First(&host)
```

### 2.3 Update / Delete 也必须带 Scope

```go
// ✅ 正确
h.db.Scopes(tenant.GinScope(c)).Model(&model.Host{}).
    Where("host_id = ?", id).Update("status", "offline")
```

### 2.4 INSERT 由 GORM 自动注入 tenant_id

```go
// 不需要手动赋值，AuthMiddleware 注入的 Identity
// 通过 GORM Hook 自动写入 tenant_id 字段（PR2d 引入 Hook）。
//
// 现阶段（PR2c）手动赋值即可：
host := model.Host{
    TenantID: tenant.MustGinIdentity(c).ID,
    HostID:   "h-12345",
    ...
}
h.db.Create(&host)
```

---

## 3. 全局表跳过规则

下列表**不要**加 Scope（PR2b 已明确跳过 `tenant_id` 字段）：

| 表 | 理由 |
|----|------|
| `tenants` / `tenant_configs` | 系统表 |
| `permissions` / `role_permissions` | RBAC 元数据 |

下列表**加了 tenant_id 字段，但业务层暂不过滤**（属配置/元数据共享，按需后续调整）：

| 表 | 备注 |
|----|------|
| `vulnerabilities` / `advisory_packages` | 漏洞库主表（多租户共享） |
| `kube_baseline_rules` / `kube_expression_templates` | 基线规则模板 |
| `components` / `component_versions` / `component_packages` | 组件管理 |
| `feature_flags` / `system_configs` | 全局配置 |
| `vuln_data_sources` / `vuln_cache` / `vuln_db_imports` / `vuln_bulletins` | 漏洞情报 |

> 这些表加了列但不参与隔离过滤。后续 PR2d/PR3 引入 VulnSync 时再决定是否租户级覆盖。

---

## 4. 平台超管路径（`/api/v2/admin/*`）

平台超管（`IsPlatformAdmin=true`）的 token 默认 `GinScope` **不追加** WHERE，可跨租户查询。

```go
// /api/v2/admin/tenants — 平台超管路径
adminRouter.Use(tenant.AdminMiddleware())
adminRouter.GET("/tenants", func(c *gin.Context) {
    var tenants []model.Tenant
    h.db.Find(&tenants) // 不需要 Scope，平台超管路径
    ...
})
```

平台超管走业务路径（如 `/api/v2/hosts`）时，必须显式 `X-Tenant-ID` Header 指明当前操作的租户（参见 [`multi-tenant.md`](multi-tenant.md) §7.3）。

---

## 5. 接入 checklist（每个 PR）

- [ ] 所有 SELECT / UPDATE / DELETE 走 `Scopes(tenant.GinScope(c))`
- [ ] 所有 INSERT 显式设 `TenantID = tenant.MustGinIdentity(c).ID`（或等待 PR2d Hook 自动注入）
- [ ] 单元测试包含跨租户隔离场景（参考 `internal/server/common/tenant/gin_test.go`）
- [ ] 集成测试包含 `X-Tenant-ID` Header 正反例（参考 `tenant_test.go::TestHeaderOverride_NormalUserCannotSpoof`）
- [ ] `make fmt && make lint && make test` 全绿

---

## 6. 后续 lint 强制（PR2d 引入）

PR2d 加入 `golangci-lint` 自定义规则：禁止特定 `model.*` 类型上的裸 `db.Find / db.First / db.Where`，必须显式 Scope。

预期规则示意（PR2d 落地）：

```yaml
# .golangci.yml
linters-settings:
  forbidigo:
    forbid:
      - p: ^h\.db\.(Find|First|Where)\(&model\.Host\b
        msg: "must use tenant.GinScope() to prevent cross-tenant leak"
```

---

## 7. 紧急回滚路径

如果某个 handler 接入后影响 v1 行为：

1. 移除该 handler 的 `Scopes(tenant.GinScope(c))` 调用
2. 该 handler 即恢复 v1 行为（默认查询所有租户数据 = 默认租户）
3. 重启 Manager 即可，不需要 DB Migration 回滚

> 该方案确保 PR2c+ 接入安全，可逐 handler 灰度。
