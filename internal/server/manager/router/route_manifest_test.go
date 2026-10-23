package router

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/api"
)

// updateManifest 用于重新生成路由 golden manifest：
//
//	go test ./internal/server/manager/router/ -run TestRouteManifest -update-routes
//
// CI 默认不带该 flag，只做只读比对；生成后由人工审查 golden diff（CI 不自增改 golden）。
var updateManifest = flag.Bool("update-routes", false, "regenerate route manifest golden file")

const manifestPath = "testdata/routes.golden"

// manifestLine 是一条精确路由清单：method + full path + 分类 (+ RBAC 权限码)。
// 精确到 method+path，杜绝“新增路由被宽泛 prefix 自动吞掉、CI 不失败”的问题。
func manifestLine(method, path string) string {
	class := api.RouteCategory(method, path)
	perm := api.RoutePermission(method, path)
	if perm == "" {
		perm = "-"
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s", method, path, class, perm)
}

// currentManifest 从真实引擎注册结果生成排序后的清单，key=「METHOD PATH」。
func currentManifest(t *testing.T) map[string]string {
	engine := buildTestEngine(t)
	m := make(map[string]string)
	for _, ri := range engine.Routes() {
		key := ri.Method + " " + ri.Path
		if _, dup := m[key]; dup {
			t.Fatalf("重复注册路由: %s", key)
		}
		m[key] = manifestLine(ri.Method, ri.Path)
	}
	return m
}

func loadManifest(t *testing.T) map[string]string {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("读取 golden manifest 失败（首次生成请运行 -update-routes）: %v", err)
	}
	m := make(map[string]string)
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) < 2 {
			t.Fatalf("golden 行格式错误: %q", line)
		}
		key := fields[0] + " " + fields[1]
		m[key] = line
	}
	return m
}

func writeManifest(t *testing.T, cur map[string]string) {
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("# 路由访问控制 golden manifest —— 由 `go test -run TestRouteManifest -update-routes` 生成。\n")
	sb.WriteString("# 格式: METHOD<TAB>PATH<TAB>CLASS<TAB>PERM(-表示无)。新增/改动路由后重新生成并人工审查 diff。\n")
	for _, k := range keys {
		sb.WriteString(cur[k])
		sb.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// diffManifests 双向比对当前路由与 golden：返回新增（golden 缺）、陈旧（实际缺）、
// 以及同一路由 class/permission 变化三类差异。
func diffManifests(cur, golden map[string]string) (newRoutes, staleRoutes, changed []string) {
	for k, line := range cur {
		g, ok := golden[k]
		if !ok {
			newRoutes = append(newRoutes, line)
		} else if g != line {
			changed = append(changed, fmt.Sprintf("golden: %s\n  actual: %s", g, line))
		}
	}
	for k, line := range golden {
		if _, ok := cur[k]; !ok {
			staleRoutes = append(staleRoutes, line)
		}
	}
	sort.Strings(newRoutes)
	sort.Strings(staleRoutes)
	sort.Strings(changed)
	return
}

// TestRouteManifest_ExactMatch 将真实 engine.Routes() 与 golden manifest 双向比对：
//   - 实际新增未登记路由 → 失败（含 hosts/nuke 之类被 prefix 吞掉的情形）；
//   - golden 陈旧条目（路由已删）→ 失败；
//   - 同一路由 class / permission 变化 → 失败。
func TestRouteManifest_ExactMatch(t *testing.T) {
	cur := currentManifest(t)
	if *updateManifest {
		writeManifest(t, cur)
		t.Logf("已重新生成 %s（%d 条路由），请人工审查 diff", manifestPath, len(cur))
		return
	}
	golden := loadManifest(t)
	newRoutes, staleRoutes, changed := diffManifests(cur, golden)

	if len(newRoutes)+len(staleRoutes)+len(changed) > 0 {
		var b strings.Builder
		if len(newRoutes) > 0 {
			b.WriteString(fmt.Sprintf("\n未登记的新路由（%d）——请分类后运行 -update-routes 重新生成 golden：\n  %s\n",
				len(newRoutes), strings.Join(newRoutes, "\n  ")))
		}
		if len(staleRoutes) > 0 {
			b.WriteString(fmt.Sprintf("\n陈旧 golden 条目（%d，路由已删除）：\n  %s\n",
				len(staleRoutes), strings.Join(staleRoutes, "\n  ")))
		}
		if len(changed) > 0 {
			b.WriteString(fmt.Sprintf("\n分类/权限变化（%d）：\n  %s\n",
				len(changed), strings.Join(changed, "\n  ")))
		}
		t.Fatal(b.String())
	}
}

// TestRouteManifest_NoUnclassified 额外断言 manifest 中没有 unclassified 类，
// 保证每条路由都有明确门禁语义。
func TestRouteManifest_NoUnclassified(t *testing.T) {
	for k, line := range currentManifest(t) {
		if strings.Contains(line, "\t"+api.RouteClassUnknown+"\t") {
			t.Errorf("路由未分类: %s", k)
		}
	}
}
