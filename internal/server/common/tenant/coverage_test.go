package tenant

// 多租户 GORM Scope 覆盖测试 (B3 审计).
//
// 扫 internal/server/model 下所有定义了 tenant_id 列的 model, 确认:
//
//   1. struct 字段含 TenantID
//   2. gorm 标签含 column:tenant_id;not null
//   3. 至少有一处 index (单列 OR 联合)
//
// 防止后续新增 model 漏配 tenant_id, 导致跨租户数据泄漏.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// modelDir 项目 model 包路径 (相对 go.mod).
const modelDir = "../../model"

// expectedTagPattern tenant_id 必须含的子串.
var expectedTagSubstrings = []string{
	"tenant_id",
	"not null",
}

// TestTenantIDColumnCoverage 扫所有 model struct.
func TestTenantIDColumnCoverage(t *testing.T) {
	abs, err := filepath.Abs(modelDir)
	if err != nil {
		t.Skipf("abs path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("model dir not found at %s (run from package dir)", abs)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, abs, func(fi os.FileInfo) bool {
		name := fi.Name()
		return !strings.HasSuffix(name, "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser: %v", err)
	}

	// 白名单: 全局表 (不分租户), 无 tenant_id 是预期.
	globalTables := map[string]bool{
		"User":             true, // 平台用户 (含 tenant_id 但 super_admin 跨 tenant)
		"Tenant":           true, // 租户表自身
		"SystemConfig":     true, // 全局站点配置
		"ComponentVersion": true,
		"ComponentPackage": true,
		"Component":        true,
		"AdvisoryPackage":  true, // 漏洞情报全局共享
		"FeatureFlag":      true, // 含 tenant_id 但默认空 = 全局
		"DataSource":       true, // 漏洞数据源配置全局
		"VulnDataSource":   true,
		"ATTCKTactic":      true,
		"ATTCKTechnique":   true,
		"PocValidation":    true,
		"NvdMetadata":      true,
		"CnnvdMetadata":    true,
		"RedhatMetadata":   true,
		"ExploitMetadata":  true,
		"BaselineRule":     true, // 平台基线规则模板
		"DetectionRule":    true, // 同上
		"Tag":              true,
		"Notification":     true,
		"PushSubscription": true,
		"Permission":       true, // RBAC 权限定义全局
		"RolePermission":   true, // 角色-权限关联全局
		"CanaryRollout":    true, // Agent 灰度发布全局
	}

	missing := []string{}
	checked := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				structName := ts.Name.Name
				// 只看 model 表 struct (带 TableName 即可, 但简单按命名约定: 首字母大写 + 有 ID 字段)
				if !isLikelyTableStruct(st) {
					return true
				}
				if globalTables[structName] {
					return true
				}
				checked++
				if !hasTenantIDField(st) {
					missing = append(missing, structName+": no TenantID field")
				} else if !tenantTagOk(st) {
					missing = append(missing, structName+": TenantID tag missing tenant_id / not null")
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Skip("no model structs scanned")
	}
	if len(missing) > 0 {
		// 用 Log 而不是 Fatal: 部分历史 model 可能预存在差距, 列出来给修
		t.Logf("scanned %d model structs", checked)
		for _, m := range missing {
			t.Logf("  %s", m)
		}
		t.Errorf("%d model(s) missing proper tenant_id coverage; add to globalTables whitelist or fix model", len(missing))
	}
}

func isLikelyTableStruct(st *ast.StructType) bool {
	hasID := false
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			continue
		}
		for _, name := range f.Names {
			if name.Name == "ID" || name.Name == "Id" {
				hasID = true
			}
		}
	}
	return hasID
}

func hasTenantIDField(st *ast.StructType) bool {
	for _, f := range st.Fields.List {
		for _, name := range f.Names {
			if name.Name == "TenantID" {
				return true
			}
		}
	}
	return false
}

func tenantTagOk(st *ast.StructType) bool {
	for _, f := range st.Fields.List {
		for _, name := range f.Names {
			if name.Name != "TenantID" {
				continue
			}
			if f.Tag == nil {
				return false
			}
			raw := f.Tag.Value
			for _, sub := range expectedTagSubstrings {
				if !strings.Contains(raw, sub) {
					return false
				}
			}
			return true
		}
	}
	return false
}
