package router

import "testing"

// TestManifestDiff_DetectsChanges 证明 golden 比对不是恒真断言：新增路由（如
// 被宽泛 prefix 自动吞掉的 hosts/nuke）、删除路由、以及 class/permission 变化
// 都必须被检出。
func TestManifestDiff_DetectsChanges(t *testing.T) {
	golden := map[string]string{
		"GET /api/v1/hosts":          "GET\t/api/v1/hosts\tauthenticated-perm\tassets:view",
		"POST /api/v1/hosts/isolate": "POST\t/api/v1/hosts/isolate\tauthenticated-perm\toperations:manage",
	}

	// 场景 1：新增未登记路由（golden 缺），必须报 new。
	curNew := map[string]string{
		"GET /api/v1/hosts":          golden["GET /api/v1/hosts"],
		"POST /api/v1/hosts/isolate": golden["POST /api/v1/hosts/isolate"],
		"POST /api/v1/hosts/nuke":    "POST\t/api/v1/hosts/nuke\tauthenticated-perm\tassets:manage",
	}
	if n, s, c := diffManifests(curNew, golden); len(n) != 1 || len(s) != 0 || len(c) != 0 {
		t.Errorf("new route: got new=%v stale=%v changed=%v, want exactly 1 new", n, s, c)
	}

	// 场景 2：路由被删除（实际缺），必须报 stale。
	curStale := map[string]string{
		"GET /api/v1/hosts": golden["GET /api/v1/hosts"],
	}
	if n, s, c := diffManifests(curStale, golden); len(n) != 0 || len(s) != 1 || len(c) != 0 {
		t.Errorf("stale route: got new=%v stale=%v changed=%v, want exactly 1 stale", n, s, c)
	}

	// 场景 3：class/permission 变化，必须报 changed。
	curChanged := map[string]string{
		"GET /api/v1/hosts":          "GET\t/api/v1/hosts\tauthenticated-perm\tassets:manage", // perm 变了
		"POST /api/v1/hosts/isolate": golden["POST /api/v1/hosts/isolate"],
	}
	if n, s, c := diffManifests(curChanged, golden); len(n) != 0 || len(s) != 0 || len(c) != 1 {
		t.Errorf("changed route: got new=%v stale=%v changed=%v, want exactly 1 changed", n, s, c)
	}
}
