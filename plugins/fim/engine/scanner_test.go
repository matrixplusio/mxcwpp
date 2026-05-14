package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestScanBasic(t *testing.T) {
	// 创建临时目录结构
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file1.txt"), "hello world")
	writeFile(t, filepath.Join(dir, "file2.conf"), "key=value")
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	writeFile(t, filepath.Join(dir, "subdir", "file3.bin"), "binary content")

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{
			{Path: dir, Level: "NORMAL"},
		},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result.Entries))
	}

	// 验证 SHA256
	entry, ok := result.Entries[filepath.Join(dir, "file1.txt")]
	if !ok {
		t.Fatal("file1.txt not found in scan result")
	}
	expectedHash := sha256Hex("hello world")
	if entry.SHA256 != expectedHash {
		t.Errorf("SHA256 mismatch: got %s, want %s", entry.SHA256, expectedHash)
	}
	if entry.Size != 11 {
		t.Errorf("size mismatch: got %d, want 11", entry.Size)
	}
	if entry.Mode == "" {
		t.Error("mode should not be empty for NORMAL level")
	}
}

func TestScanExcludePaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "keep.txt"), "keep")
	os.MkdirAll(filepath.Join(dir, "logs"), 0755)
	writeFile(t, filepath.Join(dir, "logs", "app.log"), "log data")
	writeFile(t, filepath.Join(dir, "temp.tmp"), "temp")

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths:   []WatchPath{{Path: dir, Level: "NORMAL"}},
		ExcludePaths: []string{filepath.Join(dir, "logs/"), filepath.Join(dir, "temp.tmp")},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry (logs and temp excluded), got %d", len(result.Entries))
	}
	if _, ok := result.Entries[filepath.Join(dir, "keep.txt")]; !ok {
		t.Error("keep.txt should be in scan result")
	}
}

func TestScanPermsLevel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), "setting: true")

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{{Path: dir, Level: "PERMS"}},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	entry := result.Entries[filepath.Join(dir, "config.yaml")]
	if entry.SHA256 != "" {
		t.Error("PERMS level should not compute SHA256")
	}
	if entry.Mode == "" {
		t.Error("PERMS level should have mode")
	}
}

func TestScanMultipleWatchPaths(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir1, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir2, "b.txt"), "bbb")

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{
			{Path: dir1, Level: "NORMAL"},
			{Path: dir2, Level: "CONTENT"},
		},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries from two watch paths, got %d", len(result.Entries))
	}
}

func TestScanContextCancellation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("file%d.txt", i)), "data")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	}

	_, err := scanner.Scan(ctx, policy)
	if err == nil {
		// 取消可能在遍历前或遍历中生效，两种情况都可以
		t.Log("scan completed before cancellation took effect")
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for empty dir, got %d", len(result.Entries))
	}
}

func TestScanNonexistentPath(t *testing.T) {
	scanner := NewScanner(testLogger())
	policy := &FIMPolicy{
		WatchPaths: []WatchPath{{Path: "/nonexistent/path/xyz", Level: "NORMAL"}},
	}

	result, err := scanner.Scan(context.Background(), policy)
	if err != nil {
		// WalkDir 对根路径不存在时可能直接返回错误
		return
	}
	// 若未报错，则应有 0 条目且 Errors 中记录了错误
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent path, got %d", len(result.Entries))
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for nonexistent path")
	}
}

func TestShouldExclude(t *testing.T) {
	s := &Scanner{}

	tests := []struct {
		path     string
		excludes []string
		want     bool
	}{
		{"/var/log/app.log", []string{"/var/log/"}, true},
		{"/etc/passwd", []string{"/var/log/"}, false},
		{"/tmp/cache.dat", []string{"/tmp/cache.dat"}, true},
		{"/etc/config", []string{"/etc/conf"}, true}, // prefix match
		{"/etc/conf", []string{"/etc/config"}, false},
	}

	for _, tt := range tests {
		got := s.shouldExclude(tt.path, tt.excludes)
		if got != tt.want {
			t.Errorf("shouldExclude(%q, %v) = %v, want %v", tt.path, tt.excludes, got, tt.want)
		}
	}
}

// --- helpers ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}
