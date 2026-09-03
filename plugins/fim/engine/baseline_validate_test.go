package engine

import "testing"

func TestValidatePolicyID(t *testing.T) {
	tests := []struct {
		name     string
		policyID string
		wantErr  bool
	}{
		{"正常 ID", "policy-001", false},
		{"带 UUID", "550e8400-e29b-41d4-a716-446655440000", false},
		{"空字符串", "", true},
		{"路径穿越 ../", "../etc/passwd", true},
		{"路径穿越 /", "/etc/passwd", true},
		{"反斜杠穿越", "..\\windows\\system32", true},
		{"中间包含 ..", "policy/../etc", true},
		{"中间包含 /", "policy/sub", true},
		{"纯数字", "12345", false},
		{"下划线和连字符", "my_policy-v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyID(tt.policyID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePolicyID(%q) error = %v, wantErr %v", tt.policyID, err, tt.wantErr)
			}
		})
	}
}

func TestBaselineStoreLoadPathTraversal(t *testing.T) {
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	store := NewBaselineStore(testLogger())

	// 尝试加载包含路径穿越的 PolicyID
	_, err := store.Load("../../../etc/passwd")
	if err == nil {
		t.Fatal("应拒绝包含路径穿越的 PolicyID")
	}

	_, err = store.Load("/etc/passwd")
	if err == nil {
		t.Fatal("应拒绝包含绝对路径的 PolicyID")
	}
}

func TestBaselineStoreSavePathTraversal(t *testing.T) {
	dir := t.TempDir()
	origDir := baselineDir
	baselineDir = dir
	t.Cleanup(func() { baselineDir = origDir })

	store := NewBaselineStore(testLogger())

	bl := &Baseline{
		PolicyID:  "../../../tmp/evil",
		Version:   1,
		CreatedAt: "2026-01-01T00:00:00Z",
		Entries:   map[string]FileEntry{},
	}

	err := store.Save(bl)
	if err == nil {
		t.Fatal("应拒绝保存包含路径穿越的基线")
	}
}
