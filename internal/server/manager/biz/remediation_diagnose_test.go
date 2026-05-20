package biz

import (
	"testing"
)

func TestDiagnoseError(t *testing.T) {
	tests := []struct {
		name    string
		stdout  string
		stderr  string
		wantHas string // 期望诊断中包含的关键词，空表示无匹配
	}{
		{
			name:    "yum package not found",
			stdout:  "No match for argument: openssl-3.0.0\nError: Nothing to do",
			stderr:  "",
			wantHas: "软件包在当前源中不存在",
		},
		{
			name:    "apt package not found",
			stdout:  "",
			stderr:  "E: Unable to locate package foobar",
			wantHas: "apt 源中找不到该包",
		},
		{
			name:    "network error",
			stdout:  "",
			stderr:  "Could not resolve host: mirrors.example.com",
			wantHas: "无法连接软件源",
		},
		{
			name:    "already latest",
			stdout:  "Nothing to do.",
			stderr:  "",
			wantHas: "当前版本已是最新",
		},
		{
			name:    "dependency conflict",
			stdout:  "Error: Depsolve Error occurred",
			stderr:  "",
			wantHas: "存在依赖冲突",
		},
		{
			name:    "permission denied",
			stdout:  "",
			stderr:  "Permission denied",
			wantHas: "权限不足",
		},
		{
			name:    "disk full",
			stdout:  "",
			stderr:  "No space left on device",
			wantHas: "磁盘空间不足",
		},
		{
			name:    "gpg check failed",
			stdout:  "Public key for pkg.rpm is not installed",
			stderr:  "",
			wantHas: "GPG 签名校验失败",
		},
		{
			name:    "lock held",
			stdout:  "",
			stderr:  "Could not get lock /var/lib/dpkg/lock",
			wantHas: "包管理器被其他进程锁定",
		},
		{
			name:    "command not found",
			stdout:  "",
			stderr:  "bash: dnf: command not found",
			wantHas: "包管理器命令未找到",
		},
		{
			name:    "timeout",
			stdout:  "",
			stderr:  "命令执行超时（超过 10 分钟）",
			wantHas: "命令执行超时",
		},
		{
			name:    "unknown error",
			stdout:  "some random error output",
			stderr:  "exit status 1",
			wantHas: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiagnoseError(tt.stdout, tt.stderr)
			if tt.wantHas == "" {
				if result != "" {
					t.Errorf("expected no diagnosis, got: %q", result)
				}
			} else {
				if result == "" {
					t.Errorf("expected diagnosis containing %q, got empty", tt.wantHas)
				}
				// 验证诊断内容包含预期关键词
				if len(result) > 0 && !containsSubstring(result, tt.wantHas) {
					t.Errorf("diagnosis %q does not contain %q", result, tt.wantHas)
				}
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
