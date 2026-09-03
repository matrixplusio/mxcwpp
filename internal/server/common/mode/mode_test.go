package mode

import "testing"

func TestMode_IsValid(t *testing.T) {
	t.Parallel()
	if !Observe.IsValid() || !Protect.IsValid() {
		t.Fatal("known modes must be valid")
	}
	if Mode("xxx").IsValid() {
		t.Fatal("unknown mode must be invalid")
	}
}

func TestResolver_GlobalDefault(t *testing.T) {
	t.Parallel()
	r := NewMemoryResolver(Observe)
	d := r.Resolve(Scope{})
	if d.Mode != Observe || d.Source != "global" {
		t.Fatalf("expected global observe, got %+v", d)
	}
}

func TestResolver_TenantOverride(t *testing.T) {
	t.Parallel()
	r := NewMemoryResolver(Observe)
	_ = r.SetTenant("t-1", Protect)
	d := r.Resolve(Scope{TenantID: "t-1"})
	if d.Mode != Protect || d.Source != "tenant" {
		t.Fatalf("expected tenant protect, got %+v", d)
	}
}

func TestResolver_HostLabelOverridesTenant(t *testing.T) {
	t.Parallel()
	r := NewMemoryResolver(Observe)
	_ = r.SetTenant("t-1", Observe)
	_ = r.SetHostLabel("t-1", "env=prod-edge", Protect)
	d := r.Resolve(Scope{TenantID: "t-1", HostLabels: map[string]string{"env": "prod-edge"}})
	if d.Mode != Protect || d.Source != "host_label" {
		t.Fatalf("expected host_label protect, got %+v", d)
	}
}

func TestResolver_RuleOverridesAll(t *testing.T) {
	t.Parallel()
	r := NewMemoryResolver(Observe)
	_ = r.SetTenant("t-1", Observe)
	_ = r.SetRule("BRUTE_FORCE_SSH", Protect)
	d := r.Resolve(Scope{TenantID: "t-1", RuleID: "BRUTE_FORCE_SSH"})
	if d.Mode != Protect || d.Source != "rule" {
		t.Fatalf("expected rule protect, got %+v", d)
	}
}

func TestShouldEnforce(t *testing.T) {
	t.Parallel()
	if ShouldEnforce(Decision{Mode: Observe}) {
		t.Fatal("observe should not enforce")
	}
	if !ShouldEnforce(Decision{Mode: Protect}) {
		t.Fatal("protect should enforce")
	}
}

func TestResolver_SetTenantRejectInvalid(t *testing.T) {
	t.Parallel()
	r := NewMemoryResolver(Observe)
	if err := r.SetTenant("", Protect); err == nil {
		t.Fatal("empty tenant_id should error")
	}
	if err := r.SetTenant("t-1", Mode("xxx")); err == nil {
		t.Fatal("invalid mode should error")
	}
}
