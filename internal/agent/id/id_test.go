package id

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitID_ReusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "agent_id")
	if err := os.WriteFile(f, []byte("  existing-id-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := InitID(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "existing-id-123" {
		t.Fatalf("got %q, want trimmed existing-id-123", got)
	}
}

func TestInitID_DerivesStableAcrossReinstall(t *testing.T) {
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(mid, []byte("abc-stable-machine-id\n"), 0644); err != nil {
		t.Fatal(err)
	}
	old := stableIDSources
	stableIDSources = []string{mid}
	defer func() { stableIDSources = old }()

	f := filepath.Join(dir, "agent_id")
	id1, err := InitID(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(id1) != 64 {
		t.Fatalf("derived id len=%d, want 64 hex", len(id1))
	}
	// 模拟重装：删 ID 文件后应重算出同一 ID
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	id2, err := InitID(f)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("reinstall changed id: %q != %q", id1, id2)
	}
}

func TestDeriveStableID_DeterministicAndSalted(t *testing.T) {
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	raw := "fixed-fingerprint"
	if err := os.WriteFile(mid, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	old := stableIDSources
	stableIDSources = []string{mid}
	defer func() { stableIDSources = old }()

	a := deriveStableID()
	b := deriveStableID()
	if a == "" || a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
	if a == raw {
		t.Fatal("derived id must not equal raw fingerprint (should be salted hash)")
	}
}

func TestDeriveStableID_NoSourceReturnsEmpty(t *testing.T) {
	old := stableIDSources
	stableIDSources = []string{filepath.Join(t.TempDir(), "does-not-exist")}
	defer func() { stableIDSources = old }()
	if got := deriveStableID(); got != "" {
		t.Fatalf("expected empty when no source, got %q", got)
	}
}
