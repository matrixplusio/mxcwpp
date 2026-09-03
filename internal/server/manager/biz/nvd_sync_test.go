package biz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// TestMatchByDescriptionPermanentlyRemoved 防止已废弃的 matchByDescription / descKeywordMap
// 被未来 dev 复活。这两个 symbol 用 substring keyword 关联 CVE 与已装软件，
// 准确性极差：CVE-2026-6482（Rapid7 Insight Agent Windows 提权）描述含 "openssl"
// 会被错关联到 Linux openssl pkg，全集群 fake vuln。
// 任何复活该机制的改动必须经过完整商业级 review。
func TestMatchByDescriptionPermanentlyRemoved(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "nvd_sync.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("解析 nvd_sync.go 失败: %v", err)
	}

	bannedSymbols := []string{"matchByDescription", "descKeywordMap"}
	ast.Inspect(node, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			if slices.Contains(bannedSymbols, decl.Name.Name) {
				t.Errorf("禁止符号 %q 被复活；keyword 匹配产生 fake vuln，仅允许 CPE/PURL/Advisory 精确匹配", decl.Name.Name)
			}
		case *ast.ValueSpec:
			for _, name := range decl.Names {
				if slices.Contains(bannedSymbols, name.Name) {
					t.Errorf("禁止符号 %q 被复活；keyword 匹配产生 fake vuln，仅允许 CPE/PURL/Advisory 精确匹配", name.Name)
				}
			}
		}
		return true
	})
}

// TestSyncNVDOnlyMatchesByCPE 验证 nvd_sync 主流程仅调用 matchCPEToSoftware，
// 不应再有任何 fallback keyword 匹配路径。
func TestSyncNVDOnlyMatchesByCPE(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "nvd_sync.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("解析 nvd_sync.go 失败: %v", err)
	}

	var seen []string
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if strings.HasPrefix(name, "matchBy") || name == "matchByDescription" {
			seen = append(seen, name)
		}
		return true
	})
	for _, name := range seen {
		t.Errorf("nvd_sync 含禁止的 keyword 匹配调用: %s", name)
	}
}
