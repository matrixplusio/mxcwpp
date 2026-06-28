package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// TestAuditCheckRegression 锁定 LINUX_AUDIT_025/026/027 的 check 逻辑，
// 防止再次出现"系统默认值已合规却被判 fail"的误报（2026-06-28 prod 实测发现）。
func TestAuditCheckRegression(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	tmp := t.TempDir()

	writeFile := func(name, content string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	lineChecker := NewFileLineMatchChecker(logger)
	checkLine := func(path, pattern, mode string) bool {
		res, err := lineChecker.Check(ctx, &CheckRule{
			Type:  "file_line_match",
			Param: []string{path, pattern, mode},
		})
		if err != nil {
			t.Fatalf("file_line_match(%s): %v", pattern, err)
		}
		return res.Pass
	}

	// AUDIT_026: 仅显式 Compress=no 才 fail；systemd 默认/注释行=压缩生效=pass。
	t.Run("AUDIT_026_compress_default_is_pass", func(t *testing.T) {
		const pat = `^\s*Compress\s*=\s*no`
		cases := []struct {
			name    string
			content string
			want    bool
		}{
			{"commented default", "#Compress=yes\n", true},
			{"explicit yes", "Compress=yes\n", true},
			{"missing key", "Storage=auto\n", true},
			{"explicit no", "Compress=no\n", false},
			{"explicit no spaced", "Compress = no\n", false},
		}
		for _, c := range cases {
			p := writeFile("journald-026-"+c.name, c.content)
			if got := checkLine(p, pat, "not_match"); got != c.want {
				t.Errorf("%s: got pass=%v want %v", c.name, got, c.want)
			}
		}
	})

	// AUDIT_027: 认旧 `$FileCreateMode 0640` 与 RHEL8/9 新语法 `FileCreateMode="0640"`；
	// 模式须 0640 或更严，0644(世界可读)仍 fail。
	t.Run("AUDIT_027_rsyslog_syntax_both", func(t *testing.T) {
		const pat = `(?:\$FileCreateMode\s+|FileCreateMode\s*=\s*")0[0-6][04]0`
		cases := []struct {
			name    string
			content string
			want    bool
		}{
			{"legacy 0640", "$FileCreateMode 0640\n", true},
			{"rainerscript 0640", "  FileCreateMode=\"0640\"\n", true},
			{"rainerscript 0600", "FileCreateMode=\"0600\"\n", true},
			{"rainerscript 0644 too loose", "FileCreateMode=\"0644\"\n", false},
			{"none", "module(load=\"imuxsock\")\n", false},
		}
		for _, c := range cases {
			p := writeFile("rsyslog-027-"+c.name, c.content)
			if got := checkLine(p, pat, "match"); got != c.want {
				t.Errorf("%s: got pass=%v want %v", c.name, got, c.want)
			}
		}
	})

	// AUDIT_025: condition any —— 显式 persistent OR 存在 /var/log/journal 目录(auto+目录=实际持久)。
	t.Run("AUDIT_025_persistent_or_journaldir", func(t *testing.T) {
		fileChecker := NewFileExistsChecker(logger)
		// 目录存在 → file_exists pass(覆盖 Storage=auto 默认持久场景)。
		dir := filepath.Join(tmp, "var-log-journal")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		res, err := fileChecker.Check(ctx, &CheckRule{Type: "file_exists", Param: []string{dir}})
		if err != nil {
			t.Fatalf("file_exists dir: %v", err)
		}
		if !res.Pass {
			t.Errorf("file_exists on existing journal dir: got pass=false want true")
		}
		// 显式 persistent → file_line_match pass。
		p := writeFile("journald-025", "Storage=persistent\n")
		if !checkLine(p, `^\s*Storage\s*=\s*persistent`, "match") {
			t.Errorf("explicit Storage=persistent: want pass")
		}
		// auto + 无目录 → 两个子检查都 fail，any=fail(真缺,保留检出)。
		missing := filepath.Join(tmp, "no-journal-dir")
		res2, _ := fileChecker.Check(ctx, &CheckRule{Type: "file_exists", Param: []string{missing}})
		pAuto := writeFile("journald-025-auto", "#Storage=auto\n")
		if res2.Pass || checkLine(pAuto, `^\s*Storage\s*=\s*persistent`, "match") {
			t.Errorf("auto+no dir: want both sub-checks fail (any=fail)")
		}
	})
}
