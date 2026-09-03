package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSingleTenant_NoMultiTenantProductSurface 多租户产品面必须保持移除状态。
//
// 产品定位是单租户 CWPP。曾存在的租户 CRUD、停用/恢复、MSSP 跨租户视图属于
// 另一条产品线（托管服务），留着会持续产生"平台支持多租户"的错误预期，
// 也会让每次改动都要照顾一条没人交付的路径。
//
// 底层 tenant_id 刻意保留（262 处过滤点统一传默认租户）：删列是高风险数据迁移，
// 收益只是少一个字段。收敛的是产品面，不是数据模型——见 docs/architecture.md。
func TestSingleTenant_NoMultiTenantProductSurface(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join(root,
		"internal", "server", "manager", "router", "testdata", "routes.golden"))
	if err != nil {
		t.Fatalf("读取路由清单失败: %v", err)
	}

	// 这些前缀代表多租户/托管产品面，不得重新出现在路由里。
	forbidden := map[string]string{
		"/api/v2/mssp":          "MSSP 跨租户控制台属托管服务产品线",
		"/api/v2/admin/tenants": "租户 CRUD / 停用恢复 / 按租户切换运行模式",
	}
	for _, line := range strings.Split(string(golden), "\n") {
		for prefix, why := range forbidden {
			if strings.Contains(line, prefix) {
				t.Errorf("多租户产品面路由重新出现: %s\n  %s\n"+
					"  单租户定位下不应存在该路径；如确需恢复请先更新产品定位文档。",
					strings.TrimSpace(line), why)
			}
		}
	}
}

// TestSingleTenant_DeadPackagesStayDeleted 已删除的多租户实现不得回归。
//
// billing / federation / mssp 在删除时均为零外部引用的死代码。
func TestSingleTenant_DeadPackagesStayDeleted(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Join("internal", "server", "manager", "biz", "billing"),
		filepath.Join("internal", "server", "manager", "biz", "federation"),
		filepath.Join("internal", "server", "manager", "biz", "mssp"),
	} {
		if _, err := os.Stat(filepath.Join(root, dir)); err == nil {
			t.Errorf("%s 已在单租户收敛中删除，不应重新出现", dir)
		}
	}
}
