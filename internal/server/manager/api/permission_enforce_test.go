package api

import "testing"

func TestRequiredPerm(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// 读 → module:view（已登记模块的读也要 view 权限）
		{"GET", "/api/v1/hosts/:host_id", "assets:view"},
		{"GET", "/api/v1/kube/clusters", "kube:view"},
		{"HEAD", "/api/v1/vulnerabilities", "vuln:view"},
		// 处置 → module:respond（模块支持 respond 时）
		{"POST", "/api/v1/alerts/:id/resolve", "alerts:respond"},
		{"POST", "/api/v1/alerts/:id/ignore", "alerts:respond"},
		{"DELETE", "/api/v1/quarantine/files/:id", "virus:respond"},
		// 处置语义但模块无 respond → 退化为 manage
		{"POST", "/api/v1/hosts/isolate", "operations:manage"},
		{"POST", "/api/v1/hosts/release", "operations:manage"},
		// 普通写 → module:manage
		{"POST", "/api/v1/hosts/restart-agent", "operations:manage"},
		{"DELETE", "/api/v1/hosts/:host_id", "assets:manage"},
		{"POST", "/api/v1/kube/clusters", "kube:manage"},
		{"POST", "/api/v1/vulnerabilities/scan", "vuln:manage"},
		{"POST", "/api/v1/remediation-tasks", "vuln:manage"},
		{"POST", "/api/v1/detection-rules", "detection:manage"},
		{"POST", "/api/v1/fim/tasks", "fim:manage"},
		{"POST", "/api/v1/rootkit/scan", "virus:manage"},
		{"POST", "/api/v1/policies", "baseline:manage"},
		{"DELETE", "/api/v1/rules/:rule_id", "baseline:manage"},
		// 未登记路由放行（读写均放行）
		{"POST", "/api/v1/auth/login", ""},
		{"GET", "/api/v1/something-unmapped", ""},
		{"POST", "/api/v1/something-unmapped", ""},
	}
	for _, c := range cases {
		if got := requiredPerm(c.method, c.path); got != c.want {
			t.Errorf("requiredPerm(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestPermissionResolverHas(t *testing.T) {
	r := &PermissionResolver{
		loaded: true,
		cache: map[string]map[string]bool{
			"ops": {"operations": true, "vuln": true},
		},
	}

	// admin 恒为 true（即便缓存无 admin 条目）
	if !r.Has("admin", "kube") {
		t.Fatal("admin 应拥有任意权限")
	}
	// 配置了权限的自定义角色
	if !r.Has("ops", "operations") {
		t.Fatal("ops 应有 operations")
	}
	if !r.Has("ops", "vuln") {
		t.Fatal("ops 应有 vuln")
	}
	if r.Has("ops", "kube") {
		t.Fatal("ops 不应有 kube")
	}
	// 默认 user 无任何写权
	if r.Has("user", "vuln") {
		t.Fatal("user 默认不应有写权限")
	}
	// 未知角色
	if r.Has("ghost", "operations") {
		t.Fatal("未知角色不应放行")
	}
}
