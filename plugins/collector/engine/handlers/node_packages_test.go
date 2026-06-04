package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsNodeBinary(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"node", true},
		{"nodejs", true},
		{"npm", false},
		{"yarn", false},
		{"pnpm", false},
		{"python3", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isNodeBinary(c.in); got != c.want {
			t.Errorf("isNodeBinary(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripProcRootForNode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/proc/1234/root/usr/bin/node", "/usr/bin/node"},
		{"/usr/bin/node", "/usr/bin/node"},       // 非 /proc 前缀原样
		{"/proc/abc/root/x", "/proc/abc/root/x"}, // pid 非数字原样
		{"/proc/123/cwd", "/proc/123/cwd"},       // 非 root/ 子路径原样
	}
	for _, c := range cases {
		if got := stripProcRootForNode(c.in); got != c.want {
			t.Errorf("stripProcRootForNode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildNPMPURL(t *testing.T) {
	cases := []struct {
		name    string
		version string
		want    string
	}{
		{"express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"@types/node", "20.0.0", "pkg:npm/@types/node@20.0.0"},
		{"@nestjs/common", "10.2.0", "pkg:npm/@nestjs/common@10.2.0"},
	}
	for _, c := range cases {
		if got := buildNPMPURL(c.name, c.version); got != c.want {
			t.Errorf("buildNPMPURL(%q,%q) = %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

func TestFindAncestorNodeModules(t *testing.T) {
	tmp, err := os.MkdirTemp("", "noderoot")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// 布局: tmp/app/src/index.js  &  tmp/app/node_modules  &  tmp/node_modules
	if err := os.MkdirAll(filepath.Join(tmp, "app/src"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "app/node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}

	roots := findAncestorNodeModules(filepath.Join(tmp, "app/src"))
	if len(roots) < 2 {
		t.Errorf("expected to find at least 2 node_modules roots, got %d: %v", len(roots), roots)
	}

	// 入口在 node_modules 内 → 应 trim 到外层后再找
	rootsInside := findAncestorNodeModules(filepath.Join(tmp, "app/node_modules/foo/lib"))
	if len(rootsInside) == 0 {
		t.Errorf("entry inside node_modules should still resolve outer roots")
	}

	// 空 / 相对路径 → nil
	if findAncestorNodeModules("") != nil {
		t.Errorf("empty startDir should return nil")
	}
	if findAncestorNodeModules("./relative") != nil {
		t.Errorf("relative startDir should return nil")
	}
}

func TestParseNodePackageJSON(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pkgjson")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	good := filepath.Join(tmp, "package.json")
	if err := os.WriteFile(good, []byte(`{"name":"express","version":"4.18.2","main":"index.js"}`), 0644); err != nil {
		t.Fatal(err)
	}
	pkg, ok := parseNodePackageJSON(good)
	if !ok {
		t.Fatalf("good package.json should parse")
	}
	if pkg["name"] != "express" || pkg["version"] != "4.18.2" {
		t.Errorf("name/version mismatch: %v", pkg)
	}
	if pkg["purl"] != "pkg:npm/express@4.18.2" {
		t.Errorf("purl = %v", pkg["purl"])
	}

	// 缺 name → false
	bad := filepath.Join(tmp, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := parseNodePackageJSON(bad); ok {
		t.Errorf("package.json without name should return false")
	}

	// 不存在 → false
	if _, ok := parseNodePackageJSON(filepath.Join(tmp, "nope.json")); ok {
		t.Errorf("missing file should return false")
	}

	// 损坏 JSON → false
	broken := filepath.Join(tmp, "broken.json")
	if err := os.WriteFile(broken, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := parseNodePackageJSON(broken); ok {
		t.Errorf("broken JSON should return false")
	}
}
