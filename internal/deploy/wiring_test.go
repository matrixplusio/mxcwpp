package deploy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/matrixplusio/mxcwpp/"

// inventoryPath 是未接线包清单。
const inventoryPath = "testdata/unwired-packages.tsv"

type pkgInfo struct {
	ImportPath string
	Imports    []string
	GoFiles    []string
}

// listPackages 以 linux/amd64 视角枚举包。
//
// 必须固定 GOOS：agent 的绝大部分代码带 linux 构建约束，在 darwin 上
// go list 看不到那些文件，于是"谁导入了谁"会得出完全不同的答案。
// 部署目标是 linux，就以 linux 为准。
func listPackages(t *testing.T, root string) []pkgInfo {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list 失败: %v\n%s", err, stderr.String())
	}

	var pkgs []pkgInfo
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("解析 go list 输出失败: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// readInventory 读取清单，返回 包 -> 原因。
func readInventory(t *testing.T, root string) map[string]string {
	t.Helper()

	f, err := os.Open(filepath.Join(root, "internal", "deploy", inventoryPath))
	if err != nil {
		t.Fatalf("读取清单失败: %v", err)
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		pkg, reason, ok := strings.Cut(text, "\t")
		if !ok || strings.TrimSpace(reason) == "" {
			t.Errorf("%s:%d 缺少原因；每个未接线的包都必须写明为什么它还在，"+
				"格式为 \"包路径<TAB>原因\"", inventoryPath, line)
			continue
		}
		out[strings.TrimSpace(pkg)] = strings.TrimSpace(reason)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNoUndeclaredUnwiredPackages 没有导入者的包必须在清单里登记。
//
// 本项目最贵的缺陷是静默失效：能力写完了、编译过了、日志干净，但没有
// 任何调用方，于是它从来没有生效过。已知的几例——AC 的规则同步与 IOC
// 同步、celengine 的清理协程、蜜罐的监听器——共同特征都是"没人导入这个包"。
// 编译器不报，测试不报，只有端到端去看有没有数据产出才会发现。
//
// 这条测试把它变成编译期就能看见的事实：包没有导入者不是错，
// 不声明才是错。
func TestNoUndeclaredUnwiredPackages(t *testing.T) {
	root := repoRootFromDeploy(t)

	pkgs := listPackages(t, root)
	imported := map[string]bool{}
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			imported[imp] = true
		}
	}

	var unwired []string
	for _, p := range pkgs {
		rel, ok := strings.CutPrefix(p.ImportPath, modulePath)
		if !ok {
			continue // 第三方依赖
		}
		if !strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "pkg/") {
			continue // cmd/ 是入口，plugins/ 是独立二进制，本就无导入者
		}
		if len(p.GoFiles) == 0 {
			continue // 只含 _test.go 的包，如 internal/deploy 自身
		}
		if !imported[p.ImportPath] {
			unwired = append(unwired, rel)
		}
	}
	sort.Strings(unwired)

	declared := readInventory(t, root)

	var undeclared []string
	seen := map[string]bool{}
	for _, pkg := range unwired {
		seen[pkg] = true
		if _, ok := declared[pkg]; !ok {
			undeclared = append(undeclared, pkg)
		}
	}
	if len(undeclared) > 0 {
		t.Errorf("以下包没有任何导入者，也不在 %s 中：\n  %s\n\n"+
			"这意味着它们编译得过、却从不执行。请接线，或删除，"+
			"或在清单里写明为什么它还留着。",
			inventoryPath, strings.Join(undeclared, "\n  "))
	}

	// 反向：清单里的包若已经接线，必须从清单移除，否则清单会逐渐失真，
	// 最后没人相信它写的还是当前状况。
	var stale []string
	for pkg := range declared {
		if !seen[pkg] {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("以下包已经有导入者，请从 %s 移除：\n  %s",
			inventoryPath, strings.Join(stale, "\n  "))
	}
}
