package model

import (
	"strings"
	"testing"
)

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
		if len(r.Permissions) == 0 {
			t.Errorf("role %q has no permissions", r.Code)
		}
		// 权限码必须是 module:action 形式
		for _, p := range r.Permissions {
			if !strings.Contains(p, ":") {
				t.Errorf("role %q perm %q not module:action", r.Code, p)
			}
		}
		if IsReadOnlyRole(r.Code) != w.readOnly {
			t.Errorf("IsReadOnlyRole(%q) = %v, want %v", r.Code, IsReadOnlyRole(r.Code), w.readOnly)
		}
		if BuiltinRoleName(r.Code) != w.name {
			t.Errorf("BuiltinRoleName(%q) = %q, want %q", r.Code, BuiltinRoleName(r.Code), w.name)
		}
	}
	if BuiltinRoleName("nonexist") != "" {
		t.Error("unknown role name must be empty")
	}
}

func TestActionModel(t *testing.T) {
	if Perm("alerts", ActionRespond) != "alerts:respond" {
		t.Errorf("Perm() = %q", Perm("alerts", ActionRespond))
	}
	m, a := SplitPerm("alerts:respond")
	if m != "alerts" || a != "respond" {
		t.Errorf("SplitPerm = %q,%q", m, a)
	}
	if !ModuleHasAction("alerts", ActionRespond) {
		t.Error("alerts should support respond")
	}
	if ModuleHasAction("dashboard", ActionManage) {
		t.Error("dashboard should not support manage")
	}
	// 审计员只读：不含任何 manage/respond
	for _, p := range func() []string {
		for _, r := range BuiltinRoles {
			if r.Code == "auditor" {
				return r.Permissions
			}
		}
		return nil
	}() {
		if _, act := SplitPerm(p); act != "view" {
			t.Errorf("auditor perm %q should be view-only", p)
		}
	}
}
