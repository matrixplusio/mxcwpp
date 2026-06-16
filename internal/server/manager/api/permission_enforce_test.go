package api

import "testing"

func TestRequiredWriteCode(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// 读操作放行
		{"GET", "/api/v1/hosts/:host_id", ""},
		{"GET", "/api/v1/kube/clusters", ""},
		{"HEAD", "/api/v1/vulnerabilities", ""},
		// 最长前缀优先：/hosts/isolate -> operations，而非 /hosts -> assets
		{"POST", "/api/v1/hosts/isolate", "operations"},
		{"POST", "/api/v1/hosts/release", "operations"},
		{"POST", "/api/v1/hosts/restart-agent", "operations"},
		{"DELETE", "/api/v1/hosts/:host_id", "assets"},
		{"POST", "/api/v1/hosts/batch-delete", "assets"},
		// 各模块写
		{"POST", "/api/v1/kube/clusters", "kube"},
		{"DELETE", "/api/v1/kube/clusters/:id", "kube"},
		{"POST", "/api/v1/vulnerabilities/scan", "vuln"},
		{"POST", "/api/v1/vulnerabilities/:id/patch", "vuln"},
		{"POST", "/api/v1/remediation-tasks", "vuln"},
		{"POST", "/api/v1/detection-rules", "detection"},
		{"POST", "/api/v1/threat-intel/sync", "detection"},
		{"POST", "/api/v1/fim/tasks", "fim"},
		{"DELETE", "/api/v1/quarantine/files/:id", "virus"},
		{"POST", "/api/v1/rootkit/scan", "virus"},
		{"POST", "/api/v1/network-block/rules", "operations"},
		{"POST", "/api/v1/policies", "baseline"},
		{"DELETE", "/api/v1/rules/:rule_id", "baseline"},
		{"POST", "/api/v1/alerts/:id/resolve", "alerts"},
		// 未登记写操作放行（如自助/未覆盖端点）
		{"POST", "/api/v1/auth/login", ""},
		{"POST", "/api/v1/something-unmapped", ""},
	}
	for _, c := range cases {
		if got := requiredWriteCode(c.method, c.path); got != c.want {
			t.Errorf("requiredWriteCode(%s %s) = %q, want %q", c.method, c.path, got, c.want)
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
