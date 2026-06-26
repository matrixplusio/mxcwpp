package model

import "testing"

func TestBuiltinRoles(t *testing.T) {
	want := map[string]struct {
		name     string
		readOnly bool
	}{
		"admin":          {"平台超管", false},
		"security_admin": {"安全管理员", false},
		"analyst":        {"安全分析师", false},
		"ops":            {"运维", false},
		"auditor":        {"审计员", true},
		"viewer":         {"只读用户", true},
	}
	if len(BuiltinRoles) != len(want) {
		t.Fatalf("BuiltinRoles count = %d, want %d", len(BuiltinRoles), len(want))
	}
	for _, r := range BuiltinRoles {
		w, ok := want[r.Code]
		if !ok {
			t.Errorf("unexpected builtin role %q", r.Code)
			continue
		}
		if r.Name != w.name {
			t.Errorf("role %q name = %q, want %q", r.Code, r.Name, w.name)
		}
		if r.ReadOnly != w.readOnly {
			t.Errorf("role %q ReadOnly = %v, want %v", r.Code, r.ReadOnly, w.readOnly)
		}
		if len(r.Permissions) == 0 {
			t.Errorf("role %q has no permissions", r.Code)
		}
		if IsReadOnlyRole(r.Code) != w.readOnly {
			t.Errorf("IsReadOnlyRole(%q) = %v, want %v", r.Code, IsReadOnlyRole(r.Code), w.readOnly)
		}
		if BuiltinRoleName(r.Code) != w.name {
			t.Errorf("BuiltinRoleName(%q) = %q, want %q", r.Code, BuiltinRoleName(r.Code), w.name)
		}
	}
	if IsReadOnlyRole("nonexist") {
		t.Error("unknown role must not be read-only")
	}
	if BuiltinRoleName("nonexist") != "" {
		t.Error("unknown role name must be empty")
	}
}
