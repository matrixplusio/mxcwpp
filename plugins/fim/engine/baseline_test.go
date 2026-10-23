package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineStoreSaveLoad(t *testing.T) {
	// 使用临时目录替换全局 baselineDir
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	store := NewBaselineStore(testLogger())

	entries := map[string]FileEntry{
		"/etc/passwd": {SHA256: "abc123", Size: 1024, Mode: "-rw-r--r--", UID: 0, GID: 0, MTime: 1000},
		"/etc/shadow": {SHA256: "def456", Size: 512, Mode: "-rw-------", UID: 0, GID: 42, MTime: 2000},
	}
	bl := store.NewBaseline("policy-001", entries)
	bl.Version = 3

	// 保存
	if err := store.Save(bl); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 验证文件存在
	if _, err := os.Stat(filepath.Join(dir, "policy-001.json")); err != nil {
		t.Fatalf("baseline file not created: %v", err)
	}

	// 加载
	loaded, err := store.Load("policy-001")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil for existing baseline")
	}
	if loaded.PolicyID != "policy-001" {
		t.Errorf("PolicyID mismatch: got %s", loaded.PolicyID)
	}
	if loaded.Version != 3 {
		t.Errorf("Version mismatch: got %d, want 3", loaded.Version)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(loaded.Entries))
	}
	if loaded.Entries["/etc/passwd"].SHA256 != "abc123" {
		t.Error("SHA256 mismatch for /etc/passwd")
	}
	if loaded.Entries["/etc/shadow"].UID != 0 {
		t.Errorf("UID mismatch for /etc/shadow: got %d", loaded.Entries["/etc/shadow"].UID)
	}
}

func TestBaselineStoreLoadNonexistent(t *testing.T) {
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	store := NewBaselineStore(testLogger())

	bl, err := store.Load("no-such-policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bl != nil {
		t.Fatal("expected nil for nonexistent baseline")
	}
}

func TestBaselineStoreLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	// 写入非法 JSON
	_ = os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0600)

	store := NewBaselineStore(testLogger())
	_, err := store.Load("bad")
	if err == nil {
		t.Fatal("expected error for corrupt baseline file")
	}
}

func TestBaselineStoreOverwrite(t *testing.T) {
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	store := NewBaselineStore(testLogger())

	// v1
	bl1 := store.NewBaseline("p1", map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
	})
	if err := store.Save(bl1); err != nil {
		t.Fatal(err)
	}

	// v2 — 新增文件，覆盖保存
	bl2 := store.NewBaseline("p1", map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
		"/b": {SHA256: "bbb", Size: 20},
	})
	bl2.Version = 2
	if err := store.Save(bl2); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load("p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 2 {
		t.Errorf("expected 2 entries after overwrite, got %d", len(loaded.Entries))
	}
	if loaded.Version != 2 {
		t.Errorf("version should be 2, got %d", loaded.Version)
	}
}

func TestNewBaseline(t *testing.T) {
	store := NewBaselineStore(testLogger())
	bl := store.NewBaseline("test-policy", map[string]FileEntry{
		"/x": {Size: 1},
	})
	if bl.PolicyID != "test-policy" {
		t.Errorf("PolicyID: got %s", bl.PolicyID)
	}
	if bl.Version != 1 {
		t.Errorf("Version: got %d, want 1", bl.Version)
	}
	if bl.CreatedAt == "" {
		t.Error("CreatedAt should not be empty")
	}
	if len(bl.Entries) != 1 {
		t.Errorf("Entries: got %d, want 1", len(bl.Entries))
	}
}

func TestBaselineJSONRoundTrip(t *testing.T) {
	bl := &Baseline{
		PolicyID:  "rt-test",
		Version:   5,
		CreatedAt: "2026-01-01T00:00:00Z",
		Entries: map[string]FileEntry{
			"/etc/hosts": {SHA256: "h1", Size: 100, Mode: "-rw-r--r--", UID: 0, GID: 0, MTime: 9999},
		},
	}
	data, err := json.Marshal(bl)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Baseline
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PolicyID != bl.PolicyID || decoded.Version != bl.Version {
		t.Error("JSON round-trip mismatch")
	}
	e := decoded.Entries["/etc/hosts"]
	if e.SHA256 != "h1" || e.Size != 100 || e.MTime != 9999 {
		t.Error("entry mismatch after round-trip")
	}
}
