package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPythonBinary(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"python", true},
		{"python3", true},
		{"python2", true},
		{"python3.8", true},
		{"python3.11", true},
		{"python2.7", true},
		{"pypy", true},
		{"pypy3", true},
		{"pypy3.10", true},
		{"node", false},
		{"java", false},
		{"sh", false},
		{"", false},
		{"py", false},
		{"ipython", false}, // wrapper，不直接被探测；ipython 实际 exec python 后被采到
	}
	for _, c := range cases {
		if got := isPythonBinary(c.in); got != c.want {
			t.Errorf("isPythonBinary(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripProcRoot(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/proc/1234/root/usr/bin/python3", "/usr/bin/python3"},
		{"/usr/bin/python3", "/usr/bin/python3"}, // 非 /proc 前缀原样
		{"/proc/abc/root/x", "/proc/abc/root/x"}, // pid 非数字原样
		{"/proc/123/cwd", "/proc/123/cwd"},       // 非 root/ 子路径原样
		{"/proc/1/root", "/proc/1/root"},         // stripped == "" 时原样
	}
	for _, c := range cases {
		if got := stripProcRoot(c.in); got != c.want {
			t.Errorf("stripProcRoot(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsValidSysPathDir(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pyspt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// 真目录 → true
	if !isValidSysPathDir(tmp) {
		t.Errorf("real dir should be valid: %q", tmp)
	}
	// 空字符串（CWD） → false
	if isValidSysPathDir("") {
		t.Errorf("empty sys.path entry should be invalid")
	}
	// 相对路径 → false
	if isValidSysPathDir("./foo") {
		t.Errorf("relative path should be invalid")
	}
	// .zip 文件 → false（即使存在）
	zipPath := filepath.Join(tmp, "egg.zip")
	_ = os.WriteFile(zipPath, []byte("PK"), 0644)
	if isValidSysPathDir(zipPath) {
		t.Errorf("zip path should be invalid: %q", zipPath)
	}
	// 不存在路径 → false
	if isValidSysPathDir(filepath.Join(tmp, "nonexistent")) {
		t.Errorf("missing path should be invalid")
	}
}

func TestParsePythonDistInfo(t *testing.T) {
	tmp, err := os.MkdirTemp("", "distinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// 构造 fake dist-info
	distDir := filepath.Join(tmp, "requests-2.31.0.dist-info")
	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatal(err)
	}
	metaContent := "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: Python HTTP for Humans.\n\n这后面的不该读\n"
	if err := os.WriteFile(filepath.Join(distDir, "METADATA"), []byte(metaContent), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, ok := parsePythonDistInfo(distDir)
	if !ok {
		t.Fatalf("parsePythonDistInfo should succeed for valid METADATA")
	}
	if pkg["name"] != "requests" {
		t.Errorf("name = %v, want 'requests'", pkg["name"])
	}
	if pkg["version"] != "2.31.0" {
		t.Errorf("version = %v, want '2.31.0'", pkg["version"])
	}
	if pkg["package_type"] != "pip" {
		t.Errorf("package_type = %v, want 'pip'", pkg["package_type"])
	}
	if pkg["purl"] != "pkg:pypi/requests@2.31.0" {
		t.Errorf("purl = %v, want 'pkg:pypi/requests@2.31.0'", pkg["purl"])
	}

	// 缺 METADATA / PKG-INFO → false
	emptyDir := filepath.Join(tmp, "broken.dist-info")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsePythonDistInfo(emptyDir); ok {
		t.Errorf("missing METADATA should return false")
	}

	// METADATA 缺 Name/Version → false
	badDir := filepath.Join(tmp, "noname.dist-info")
	if err := os.MkdirAll(badDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "METADATA"), []byte("Metadata-Version: 2.1\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsePythonDistInfo(badDir); ok {
		t.Errorf("METADATA without Name/Version should return false")
	}
}
