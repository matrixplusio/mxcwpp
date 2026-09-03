package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLogsMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := RunLogs(LogsOptions{LogFile: "/nonexistent/path.log", Lines: 10}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "日志文件不存在") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunLogsTail(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "agent.log")
	content := "line1\nline2\nline3\nline4\nline5\n"
	if err := os.WriteFile(logPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := RunLogs(LogsOptions{LogFile: logPath, Lines: 2}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if !strings.Contains(got, "line4") || !strings.Contains(got, "line5") {
		t.Errorf("expected last 2 lines, got: %q", got)
	}
	if strings.Contains(got, "line1") {
		t.Errorf("expected only last 2 lines, got: %q", got)
	}
}
