package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================
// compare / compareEntries 单元测试
// ============================================================

func TestCompareNoChange(t *testing.T) {
	entries := map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10, Mode: "-rw-r--r--", UID: 0, GID: 0, MTime: 100},
		"/b": {SHA256: "bbb", Size: 20, Mode: "-rw-------", UID: 0, GID: 0, MTime: 200},
	}
	bl := &Baseline{PolicyID: "p1", Entries: entries}
	scan := &ScanResult{Entries: entries}

	events := compare(bl, scan)
	if len(events) != 0 {
		t.Errorf("expected 0 events for identical state, got %d", len(events))
	}
}

func TestCompareAddedFiles(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
		"/b": {SHA256: "bbb", Size: 20},
		"/c": {SHA256: "ccc", Size: 30},
	}}

	events := compare(bl, scan)
	added := filterEvents(events, "added")
	if len(added) != 2 {
		t.Errorf("expected 2 added events, got %d", len(added))
	}
	paths := map[string]bool{}
	for _, e := range added {
		paths[e.FilePath] = true
	}
	if !paths["/b"] || !paths["/c"] {
		t.Error("missing added file paths")
	}
}

func TestCompareRemovedFiles(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
		"/b": {SHA256: "bbb", Size: 20},
		"/c": {SHA256: "ccc", Size: 30},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 10},
	}}

	events := compare(bl, scan)
	removed := filterEvents(events, "removed")
	if len(removed) != 2 {
		t.Errorf("expected 2 removed events, got %d", len(removed))
	}
}

func TestCompareChangedHashOnly(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/etc/config": {SHA256: "old-hash", Size: 100, Mode: "-rw-r--r--", UID: 0, GID: 0},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/etc/config": {SHA256: "new-hash", Size: 100, Mode: "-rw-r--r--", UID: 0, GID: 0},
	}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 changed event, got %d", len(events))
	}
	ev := events[0]
	if ev.ChangeType != "changed" {
		t.Errorf("expected changed, got %s", ev.ChangeType)
	}
	if !ev.ChangeDetail.HashChanged {
		t.Error("HashChanged should be true")
	}
	if ev.ChangeDetail.HashBefore != "old-hash" || ev.ChangeDetail.HashAfter != "new-hash" {
		t.Error("hash before/after mismatch")
	}
	if ev.ChangeDetail.PermissionChanged {
		t.Error("PermissionChanged should be false")
	}
	if ev.ChangeDetail.OwnerChanged {
		t.Error("OwnerChanged should be false")
	}
}

func TestCompareChangedPermOnly(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/f": {SHA256: "same", Size: 50, Mode: "-rw-r--r--", UID: 0, GID: 0},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/f": {SHA256: "same", Size: 50, Mode: "-rwxr-xr-x", UID: 0, GID: 0},
	}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	d := events[0].ChangeDetail
	if !d.PermissionChanged {
		t.Error("PermissionChanged should be true")
	}
	if d.ModeBefore != "-rw-r--r--" || d.ModeAfter != "-rwxr-xr-x" {
		t.Error("mode before/after mismatch")
	}
	if d.HashChanged {
		t.Error("HashChanged should be false")
	}
}

func TestCompareChangedOwner(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/f": {SHA256: "x", Size: 10, Mode: "-rw-r--r--", UID: 0, GID: 0},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/f": {SHA256: "x", Size: 10, Mode: "-rw-r--r--", UID: 1000, GID: 1000},
	}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].ChangeDetail.OwnerChanged {
		t.Error("OwnerChanged should be true")
	}
}

func TestCompareChangedSize(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/f": {SHA256: "x", Size: 100, Mode: "-rw-r--r--"},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/f": {SHA256: "x", Size: 200, Mode: "-rw-r--r--"},
	}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	d := events[0].ChangeDetail
	if d.SizeBefore != "100" || d.SizeAfter != "200" {
		t.Errorf("size before/after: got %s / %s", d.SizeBefore, d.SizeAfter)
	}
}

func TestCompareMultipleChanges(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/f": {SHA256: "old", Size: 100, Mode: "-rw-r--r--", UID: 0, GID: 0},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/f": {SHA256: "new", Size: 200, Mode: "-rwxr-xr-x", UID: 1000, GID: 1000},
	}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	d := events[0].ChangeDetail
	if !d.HashChanged || !d.PermissionChanged || !d.OwnerChanged {
		t.Error("all change flags should be true")
	}
	if d.SizeBefore != "100" || d.SizeAfter != "200" {
		t.Error("size before/after mismatch")
	}
}

func TestCompareMixed(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/keep":    {SHA256: "same", Size: 10},
		"/changed": {SHA256: "old", Size: 10},
		"/removed": {SHA256: "rm", Size: 5},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/keep":    {SHA256: "same", Size: 10},
		"/changed": {SHA256: "new", Size: 10},
		"/added":   {SHA256: "add", Size: 8},
	}}

	events := compare(bl, scan)
	if len(events) != 3 {
		t.Fatalf("expected 3 events (added+removed+changed), got %d", len(events))
	}
	if len(filterEvents(events, "added")) != 1 {
		t.Error("expected 1 added")
	}
	if len(filterEvents(events, "removed")) != 1 {
		t.Error("expected 1 removed")
	}
	if len(filterEvents(events, "changed")) != 1 {
		t.Error("expected 1 changed")
	}
}

func TestCompareEmptyBaseline(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{}}
	scan := &ScanResult{Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 1},
		"/b": {SHA256: "bbb", Size: 2},
	}}

	events := compare(bl, scan)
	if len(events) != 2 {
		t.Fatalf("expected 2 added events, got %d", len(events))
	}
	for _, e := range events {
		if e.ChangeType != "added" {
			t.Errorf("expected added, got %s", e.ChangeType)
		}
	}
}

func TestCompareEmptyScan(t *testing.T) {
	bl := &Baseline{PolicyID: "p1", Entries: map[string]FileEntry{
		"/a": {SHA256: "aaa", Size: 1},
	}}
	scan := &ScanResult{Entries: map[string]FileEntry{}}

	events := compare(bl, scan)
	if len(events) != 1 {
		t.Fatalf("expected 1 removed event, got %d", len(events))
	}
	if events[0].ChangeType != "removed" {
		t.Errorf("expected removed, got %s", events[0].ChangeType)
	}
}

func TestCompareEntriesNoChange(t *testing.T) {
	e := FileEntry{SHA256: "x", Size: 10, Mode: "-rw-r--r--", UID: 0, GID: 0, MTime: 100}
	result := compareEntries(e, e)
	if result != nil {
		t.Error("expected nil for identical entries")
	}
}

func TestCompareEntriesPermsLevelNoHash(t *testing.T) {
	// PERMS 级别没有 SHA256，仅比较权限
	old := FileEntry{Size: 10, Mode: "-rw-r--r--", UID: 0, GID: 0}
	cur := FileEntry{Size: 10, Mode: "-rwxr-xr-x", UID: 0, GID: 0}
	result := compareEntries(old, cur)
	if result == nil {
		t.Fatal("expected change for mode difference")
	}
	if !result.PermissionChanged {
		t.Error("PermissionChanged should be true")
	}
	if result.HashChanged {
		t.Error("HashChanged should be false when both hashes empty")
	}
}

// ============================================================
// Engine 集成测试
// ============================================================

func TestEngineFirstScan(t *testing.T) {
	// 准备临时文件和临时基线目录
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hello.txt"), "hello")
	writeFile(t, filepath.Join(dir, "world.txt"), "world")

	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	taskData := marshalTaskData(t, &FIMPolicy{
		PolicyID:   "test-policy",
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	})

	engine := NewEngine(testLogger())
	result, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// 首次扫描应返回 IsInitialBaseline=true
	if !result.IsInitialBaseline {
		t.Error("expected IsInitialBaseline=true for first scan")
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for initial scan, got %d", len(result.Events))
	}
	if len(result.Snapshot) != 2 {
		t.Errorf("expected 2 entries in snapshot, got %d", len(result.Snapshot))
	}
	if result.Summary.TotalEntries != 2 {
		t.Errorf("expected TotalEntries=2, got %d", result.Summary.TotalEntries)
	}

	// 验证基线文件已保存
	bl, err := NewBaselineStore(testLogger()).Load("test-policy")
	if err != nil {
		t.Fatal(err)
	}
	if bl == nil {
		t.Fatal("baseline not saved after first scan")
	}
	if len(bl.Entries) != 2 {
		t.Errorf("baseline entries: got %d, want 2", len(bl.Entries))
	}
}

func TestEngineSecondScanNoChange(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file.txt"), "content")

	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	taskData := marshalTaskData(t, &FIMPolicy{
		PolicyID:   "p-nochange",
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	})

	engine := NewEngine(testLogger())

	// 第一次扫描 — 创建基线
	_, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}

	// 第二次扫描 — 无变更
	result, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsInitialBaseline {
		t.Error("second scan should not be initial baseline")
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for unchanged files, got %d", len(result.Events))
	}
}

func TestEngineSecondScanWithChanges(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "keep.txt"), "keep")
	writeFile(t, filepath.Join(dir, "modify.txt"), "before")
	writeFile(t, filepath.Join(dir, "delete.txt"), "will be deleted")

	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	taskData := marshalTaskData(t, &FIMPolicy{
		PolicyID:   "p-changes",
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	})

	engine := NewEngine(testLogger())

	// 第一次扫描
	r1, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.IsInitialBaseline {
		t.Fatal("first scan should be initial baseline")
	}

	// 修改文件
	writeFile(t, filepath.Join(dir, "modify.txt"), "after modification")
	os.Remove(filepath.Join(dir, "delete.txt"))
	writeFile(t, filepath.Join(dir, "new.txt"), "new file")

	// 第二次扫描
	r2, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}

	if r2.IsInitialBaseline {
		t.Error("second scan should not be initial baseline")
	}

	added := filterEvents(r2.Events, "added")
	removed := filterEvents(r2.Events, "removed")
	changed := filterEvents(r2.Events, "changed")

	if len(added) != 1 {
		t.Errorf("expected 1 added, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(removed))
	}
	if len(changed) != 1 {
		t.Errorf("expected 1 changed, got %d", len(changed))
	}

	// 验证 summary
	if r2.Summary.AddedEntries != 1 {
		t.Errorf("summary added: got %d", r2.Summary.AddedEntries)
	}
	if r2.Summary.RemovedEntries != 1 {
		t.Errorf("summary removed: got %d", r2.Summary.RemovedEntries)
	}
	if r2.Summary.ChangedEntries != 1 {
		t.Errorf("summary changed: got %d", r2.Summary.ChangedEntries)
	}

	// 验证 changed 事件有 hash before/after
	if len(changed) > 0 {
		d := changed[0].ChangeDetail
		if !d.HashChanged {
			t.Error("changed event should have HashChanged=true")
		}
		if d.HashBefore == "" || d.HashAfter == "" {
			t.Error("changed event should have hash before/after")
		}
	}
}

func TestEngineClassification(t *testing.T) {
	dir := t.TempDir()

	// 初始基线只有一个文件
	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	writeFile(t, filepath.Join(dir, "file.txt"), "initial")

	taskData := marshalTaskData(t, &FIMPolicy{
		PolicyID:   "p-classify",
		WatchPaths: []WatchPath{{Path: dir, Level: "NORMAL"}},
	})

	engine := NewEngine(testLogger())

	// 第一次扫描
	_, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}

	// 添加文件并第二次扫描
	writeFile(t, filepath.Join(dir, "newfile.txt"), "new")
	r2, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}

	// 事件应被 Classify 分类（非关键路径 → low/other，但 added 提升为 medium）
	added := filterEvents(r2.Events, "added")
	if len(added) != 1 {
		t.Fatalf("expected 1 added event, got %d", len(added))
	}
	ev := added[0]
	if ev.Severity == "" {
		t.Error("severity should not be empty after classification")
	}
	if ev.Category == "" {
		t.Error("category should not be empty after classification")
	}
}

func TestEngineSaveBaseline(t *testing.T) {
	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	engine := NewEngine(testLogger())

	bl := Baseline{
		PolicyID:  "from-server",
		Version:   5,
		CreatedAt: "2026-01-01T00:00:00Z",
		Entries: map[string]FileEntry{
			"/etc/test": {SHA256: "server-hash", Size: 42},
		},
	}
	data, _ := json.Marshal(bl)

	if err := engine.SaveBaseline(data); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := NewBaselineStore(testLogger()).Load("from-server")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("baseline not found after SaveBaseline")
	}
	if loaded.Version != 5 {
		t.Errorf("version: got %d, want 5", loaded.Version)
	}
	if loaded.Entries["/etc/test"].SHA256 != "server-hash" {
		t.Error("entry SHA256 mismatch")
	}
}

func TestEngineParsePolicyError(t *testing.T) {
	engine := NewEngine(testLogger())

	// 无效 JSON
	_, err := engine.Execute(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	// 空 watch_paths
	taskData := marshalTaskData(t, &FIMPolicy{PolicyID: "p1"})
	_, err = engine.Execute(context.Background(), taskData)
	if err == nil {
		t.Fatal("expected error for empty watch paths")
	}
}

func TestEnginePermsLevel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), "setting: true")

	blDir := t.TempDir()
	origDir := baselineDir
	baselineDir = blDir
	t.Cleanup(func() { baselineDir = origDir })

	taskData := marshalTaskData(t, &FIMPolicy{
		PolicyID:   "p-perms",
		WatchPaths: []WatchPath{{Path: dir, Level: "PERMS"}},
	})

	engine := NewEngine(testLogger())
	result, err := engine.Execute(context.Background(), taskData)
	if err != nil {
		t.Fatal(err)
	}

	// PERMS 级别不应有 SHA256
	for path, entry := range result.Snapshot {
		if entry.SHA256 != "" {
			t.Errorf("PERMS level should not compute SHA256 for %s", path)
		}
		if entry.Mode == "" {
			t.Errorf("PERMS level should have mode for %s", path)
		}
	}
}

// ============================================================
// helpers
// ============================================================

func marshalTaskData(t *testing.T, policy *FIMPolicy) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return data
}

func filterEvents(events []FIMEvent, changeType string) []FIMEvent {
	var result []FIMEvent
	for _, e := range events {
		if e.ChangeType == changeType {
			result = append(result, e)
		}
	}
	return result
}
