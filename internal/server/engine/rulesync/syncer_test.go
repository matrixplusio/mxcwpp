package rulesync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// writeYAML 在 dir 下写入 YAML 文件，返回路径
func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseRuleFile(t *testing.T) {
	dir := t.TempDir()
	logger := zaptest.NewLogger(t)

	s := New(config.RuleSyncConfig{LocalDir: dir}, nil, logger)

	yamlContent := `rules:
  - name: reverse_shell_detect
    expression: 'exe == "/bin/bash" && remote_addr != ""'
    severity: critical
    category: backdoor
    mitre_id: T1059.004
    data_types: [3000]
    description: 反弹 Shell 检测
  - name: crypto_miner_detect
    expression: 'exe contains "xmrig"'
    severity: high
    category: cryptomining
    mitre_id: T1496
    data_types: [3000]
    description: 挖矿进程检测
`
	path := writeYAML(t, dir, "test-rules.yaml", yamlContent)

	rules, err := s.parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile 失败: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("预期 2 条规则，实际 %d", len(rules))
	}

	r := rules[0]
	if r.Name != "reverse_shell_detect" {
		t.Errorf("Name = %q, want reverse_shell_detect", r.Name)
	}
	if r.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", r.Severity)
	}
	if r.MitreID != "T1059.004" {
		t.Errorf("MitreID = %q, want T1059.004", r.MitreID)
	}
	if len(r.DataTypes) != 1 || r.DataTypes[0] != "3000" {
		t.Errorf("DataTypes = %v, want [3000]", r.DataTypes)
	}

	r2 := rules[1]
	if r2.Name != "crypto_miner_detect" {
		t.Errorf("Name = %q, want crypto_miner_detect", r2.Name)
	}
	if r2.Category != "cryptomining" {
		t.Errorf("Category = %q, want cryptomining", r2.Category)
	}
}

func TestParseRuleFileEmpty(t *testing.T) {
	dir := t.TempDir()
	logger := zaptest.NewLogger(t)

	s := New(config.RuleSyncConfig{LocalDir: dir}, nil, logger)

	// YAML 无 rules 字段
	path := writeYAML(t, dir, "empty.yaml", "version: 1\n")

	rules, err := s.parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile 失败: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("预期 0 条规则，实际 %d", len(rules))
	}
}

func TestParseRuleFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	logger := zaptest.NewLogger(t)

	s := New(config.RuleSyncConfig{LocalDir: dir}, nil, logger)

	// 非法 YAML（无法解析）
	path := writeYAML(t, dir, "bad.yaml", "{{{{invalid yaml")

	_, err := s.parseRuleFile(path)
	if err == nil {
		t.Error("预期解析失败，但成功了")
	}
}

func TestParseRulesDir(t *testing.T) {
	dir := t.TempDir()
	logger := zaptest.NewLogger(t)

	// 根目录放一个 yaml
	writeYAML(t, dir, "root.yaml", `rules:
  - name: rule_a
    expression: 'true'
    severity: low
`)

	// rules/ 子目录放一个 yml
	rulesDir := filepath.Join(dir, "rules")
	if err := os.Mkdir(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeYAML(t, rulesDir, "sub.yml", `rules:
  - name: rule_b
    expression: 'true'
    severity: medium
`)

	s := New(config.RuleSyncConfig{LocalDir: dir}, nil, logger)
	rules, err := s.parseRulesDir()
	if err != nil {
		t.Fatalf("parseRulesDir 失败: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("预期 2 条规则（根目录+子目录），实际 %d", len(rules))
	}

	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	if !names["rule_a"] || !names["rule_b"] {
		t.Errorf("缺少规则: got names=%v", names)
	}
}

func TestNewDefaults(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	s := New(config.RuleSyncConfig{}, nil, logger)

	if s.cfg.Branch != "main" {
		t.Errorf("Branch 默认值 = %q, want main", s.cfg.Branch)
	}
	if s.cfg.LocalDir != "/var/mxcwpp/rules-repo" {
		t.Errorf("LocalDir 默认值 = %q, want /var/mxcwpp/rules-repo", s.cfg.LocalDir)
	}
	if s.cfg.Interval != 10*time.Minute {
		t.Errorf("Interval 默认值 = %v, want 10m", s.cfg.Interval)
	}
}
