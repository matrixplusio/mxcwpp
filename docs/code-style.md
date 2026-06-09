# 代码风格与质量规范 (v2.0)

> **强制约束**:本规范由 `.golangci.yml` 自动校验,违反会被 CI 拒绝。
> 本文档由 PR7 引入,后续 PR 必须遵守。

---

## 1. 日志

### 1.1 强制使用 `go.uber.org/zap`

```go
// ❌ 禁止
fmt.Println("user logged in:", username)
log.Printf("user %s logged in", username)

// ✅ 正确
logger.Info("用户登录",
    zap.String("username", username),
    zap.String("ip", clientIP),
)
```

### 1.2 例外(CLI 用户面向 stdout)

以下场景允许 `fmt.Print*`(`.golangci.yml` 已配置例外):

- `cmd/` 下所有 main 入口的启动信息(version / build time / config path)
- `internal/deploy/cluster/` 的 mxctl deploy 进度输出
- `internal/agent/updater/` 的 Agent 自更新 CLI 输出

判断标准:**给真人在终端看的 → fmt.Print 允许;给运维 / SIEM / 链路追踪的日志 → 必须 zap**。

### 1.3 zap 字段规范

```go
// ✅ 字段名用小写下划线 (Snake_case)
logger.Error("查询主机失败",
    zap.String("host_id", id),
    zap.String("tenant_id", tid),
    zap.Error(err),
)

// ❌ 不要混用驼峰 / 短下划线 / 大写
logger.Error("...", zap.String("hostId", id))    // ❌
logger.Error("...", zap.String("Host-ID", id))   // ❌
```

字段优先级(按业务重要性): `tenant_id` > `host_id`/`agent_id` > `rule_id`/`task_id` > 业务字段 > `error`(永远在最后)。

---

## 2. HTTP 响应

### 2.1 强制使用 `internal/server/manager/api/response.go` 的 helper

```go
// ✅ 正确
api.Success(c, gin.H{"data": result})
api.SuccessWithMessage(c, "操作成功", result)
api.SuccessPaginated(c, total, items)
api.Created(c, newRecord)
api.BadRequest(c, "请求参数错误: " + err.Error())
api.NotFound(c, "主机不存在")
api.Conflict(c, "用户名已存在")
api.InternalError(c, "查询失败")
api.Unauthorized(c, "未授权")
api.Forbidden(c, "无权限")
api.TooManyRequests(c, "请求过于频繁")
api.ServiceUnavailable(c, "服务不可用", retryInfo)

// ❌ 禁止裸 c.JSON
c.JSON(http.StatusBadRequest, gin.H{"error": "xxx"})       // ❌
c.JSON(http.StatusOK, gin.H{"code": 0, "data": x})         // ❌
```

### 2.2 例外(内部协议)

内部服务间(AC↔Manager)的协议允许裸 `c.JSON`,因为有自定义协议字段(如 `{"status":"registered","action":"re-register"}`)。

文件必须在头部注释明确说明:

```go
// 注意:本文件 c.JSON 直接调用不使用 response.go 助手,
// 因为这是 AgentCenter ↔ Manager 内部协议,协议字段固定。
```

---

## 3. 错误处理

### 3.1 用 `fmt.Errorf` 包装

```go
// ✅ 正确
if err := db.Find(&hosts).Error; err != nil {
    return fmt.Errorf("查询主机列表失败: %w", err)
}

// ❌ 禁止
if err := db.Find(&hosts).Error; err != nil {
    return errors.New("query failed")  // 丢失原始错误链
}
if err := db.Find(&hosts).Error; err != nil {
    return err  // 缺上下文,调用方难定位
}
```

### 3.2 哨兵错误用 `errors.Is`

```go
// ✅ 正确
if errors.Is(err, gorm.ErrRecordNotFound) { ... }
if errors.Is(err, context.Canceled) { ... }

// ❌ 禁止
if err == gorm.ErrRecordNotFound { ... }  // ❌ wrap 后不工作
```

### 3.3 panic 仅限于"绝不应该发生"的情况

```go
// ✅ 启动时强校验,panic 让程序立即失败
registry.MustRegister(driver)

// ❌ 业务逻辑里 panic
panic("invalid input")  // ❌ 应该 return error
```

---

## 4. 多租户

### 4.1 所有业务查询必须走 tenant Scope

```go
// ✅ 正确
db.Scopes(tenant.GinScope(c)).Find(&hosts)
db.Scopes(tenant.GinScope(c)).Where("host_id = ?", id).First(&host)

// ❌ 禁止
db.Find(&hosts)                                  // ❌ 跨租户穿越
db.Where("host_id = ?", id).First(&host)         // ❌
```

详见 [`multi-tenant-rollout.md`](multi-tenant-rollout.md)。

### 4.2 全局表豁免

- `Tenant` / `TenantConfig` / `Permission` / `RolePermission` 等系统表
- 漏洞库主表 `Vulnerability` / `AdvisoryPackage` 等共享数据
- 不需要 tenant Scope,但代码层应有注释说明

---

## 5. 公共代码抽取

### 5.1 抽取原则

- 3 处以上重复 → 立即抽 helper 到 `internal/server/common/<topic>/`
- helper 必须有包级 doc + 单元测试
- 命名以"动词 + 对象"为主(`BuildHTTPClient` / `RegisterAutoInjectHook`)

### 5.2 当前已抽取的 common 包

| 包 | 用途 |
|---|------|
| `internal/server/common/kafka` | Kafka Producer / Topic 路由 / MQMessage |
| `internal/server/common/tenant` | 多租户 Identity / Scope / Middleware / Hook |
| `internal/server/common/canary` | 灰度发布 Driver / Registry |
| `internal/server/common/observability` | OTel 追踪初始化 |

---

## 6. 测试

### 6.1 必须有单元测试的代码

- 所有 `internal/server/common/` 包(基础设施,影响全局)
- 关键业务 handler(多租户 / 鉴权 / 修复)
- 数据迁移函数

### 6.2 测试命名 + 结构

```go
// ✅ 命名: Test<被测函数>_<场景> 或 Test<被测函数>_<期望>
func TestGinScope_IsolatesTenants(t *testing.T) { ... }
func TestRegistry_RejectDuplicate(t *testing.T) { ... }
func TestAdminTenants_NormalUserBlocked(t *testing.T) { ... }

// ✅ 并发测试用 t.Parallel()
func TestX(t *testing.T) {
    t.Parallel()
    ...
}

// ✅ 表驱动用 t.Run
for _, tc := range cases {
    t.Run(tc.name, func(t *testing.T) { ... })
}
```

---

## 7. 包 doc

每个新包必须有 `// Package xxx 提供 ...` 风格的包级 doc,且:

- 解释职责 + 边界(不做什么)
- 给典型用法 5 行内代码示例
- 引用相关设计文档

---

## 8. 代码评审 checklist

每个 PR 自检:

- [ ] zap 日志 + 字段命名 snake_case + 优先 tenant_id/host_id
- [ ] HTTP 响应走 `response.go` helper(内部协议除外)
- [ ] `fmt.Errorf` wrap 错误,`errors.Is` 比对哨兵
- [ ] 业务查询带 `tenant.GinScope`
- [ ] 3 处以上重复抽 common
- [ ] 新增 common 包带单元测试
- [ ] `make fmt && make lint && make test` 全绿
- [ ] commit 信息无 AI 字眼,中文,目的为先

---

## 9. 自动校验

| 工具 | 配置 | 拦截内容 |
|------|------|----------|
| `golangci-lint` | `.golangci.yml` | fmt.Print* / log.* / errcheck / unused / static analysis |
| `make fmt` | `gofmt` | 格式化 |
| `make test` | `go test ./...` | 单元/集成测试 |

CI 必须三者全绿才能 merge。
