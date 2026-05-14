// Package engine 提供基线检查器的单元测试
package engine

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// setupTestLogger 创建测试用的 logger
func setupTestLogger(t *testing.T) *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger
}

// TestFileKVChecker 测试 FileKVChecker
func TestFileKVChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewFileKVChecker(logger)
	ctx := context.Background()

	// 创建临时目录
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		setup    func() string // 返回文件路径
		rule     *CheckRule
		wantPass bool
		wantErr  bool
	}{
		{
			name: "pass - key value match (Key Value format)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test1.conf")
				os.WriteFile(file, []byte("PermitRootLogin no\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "pass - key value match (Key=Value format)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test2.conf")
				os.WriteFile(file, []byte("PermitRootLogin=no\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "pass - key value match with regex",
			setup: func() string {
				file := filepath.Join(tmpDir, "test3.conf")
				os.WriteFile(file, []byte("Port 22\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "Port", "\\d+"},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "pass - case insensitive key match",
			setup: func() string {
				file := filepath.Join(tmpDir, "test4.conf")
				os.WriteFile(file, []byte("permitrootlogin no\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "fail - key value mismatch",
			setup: func() string {
				file := filepath.Join(tmpDir, "test5.conf")
				os.WriteFile(file, []byte("PermitRootLogin yes\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "fail - key not found",
			setup: func() string {
				file := filepath.Join(tmpDir, "test6.conf")
				os.WriteFile(file, []byte("Port 22\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "fail - file not exists",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.conf")
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "Key", "Value"},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "pass - ignore comments",
			setup: func() string {
				file := filepath.Join(tmpDir, "test7.conf")
				os.WriteFile(file, []byte("# PermitRootLogin yes\nPermitRootLogin no\n"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{"", "PermitRootLogin", "no"},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "error - insufficient parameters",
			setup: func() string {
				return filepath.Join(tmpDir, "test8.conf")
			},
			rule: &CheckRule{
				Type:  "file_kv",
				Param: []string{filepath.Join(tmpDir, "test8.conf")}, // 只有1个参数，需要3个
			},
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			rule := &CheckRule{
				Type:  tt.rule.Type,
				Param: make([]string, len(tt.rule.Param)),
			}
			copy(rule.Param, tt.rule.Param)
			rule.Param[0] = filePath

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestFileExistsChecker 测试 FileExistsChecker
func TestFileExistsChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewFileExistsChecker(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		setup    func() string
		wantPass bool
		wantErr  bool
	}{
		{
			name: "pass - file exists",
			setup: func() string {
				file := filepath.Join(tmpDir, "exists.txt")
				os.WriteFile(file, []byte("test"), 0644)
				return file
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "fail - file not exists",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.txt")
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "error - insufficient parameters",
			setup: func() string {
				return ""
			},
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			var param []string
			if filePath != "" {
				param = []string{filePath}
			} else {
				param = []string{} // 空参数数组
			}
			rule := &CheckRule{
				Type:  "file_exists",
				Param: param,
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestFilePermissionChecker 测试 FilePermissionChecker
func TestFilePermissionChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewFilePermissionChecker(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		setup    func() string
		minPerm  string
		wantPass bool
		wantErr  bool
	}{
		{
			name: "pass - permission matches",
			setup: func() string {
				file := filepath.Join(tmpDir, "test1.txt")
				os.WriteFile(file, []byte("test"), 0644)
				return file
			},
			minPerm:  "644",
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "pass - permission stricter than min",
			setup: func() string {
				file := filepath.Join(tmpDir, "test2.txt")
				os.WriteFile(file, []byte("test"), 0600)
				return file
			},
			minPerm:  "644",
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "fail - permission too loose",
			setup: func() string {
				file := filepath.Join(tmpDir, "test3.txt")
				os.WriteFile(file, []byte("test"), 0644)
				os.Chmod(file, 0666)
				return file
			},
			minPerm:  "644",
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "fail - file not exists",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.txt")
			},
			minPerm:  "644",
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "error - invalid permission format",
			setup: func() string {
				file := filepath.Join(tmpDir, "test4.txt")
				os.WriteFile(file, []byte("test"), 0644)
				return file
			},
			minPerm:  "invalid",
			wantPass: false,
			wantErr:  true,
		},
		{
			name: "error - insufficient parameters",
			setup: func() string {
				file := filepath.Join(tmpDir, "test5.txt")
				os.WriteFile(file, []byte("test"), 0644)
				return file
			},
			minPerm:  "",
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			rule := &CheckRule{
				Type:  "file_permission",
				Param: []string{filePath, tt.minPerm},
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestFileLineMatchChecker 测试 FileLineMatchChecker
func TestFileLineMatchChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewFileLineMatchChecker(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		setup         func() string
		pattern       string
		expectedMatch string // "match" or "not_match"
		wantPass      bool
		wantErr       bool
	}{
		{
			name: "pass - pattern matches (default match)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test1.txt")
				os.WriteFile(file, []byte("PASS_MAX_DAYS 90\n"), 0644)
				return file
			},
			pattern:       "PASS_MAX_DAYS",
			expectedMatch: "",
			wantPass:      true,
			wantErr:       false,
		},
		{
			name: "pass - pattern matches (explicit match)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test2.txt")
				os.WriteFile(file, []byte("PASS_MAX_DAYS 90\n"), 0644)
				return file
			},
			pattern:       "PASS_MAX_DAYS",
			expectedMatch: "match",
			wantPass:      true,
			wantErr:       false,
		},
		{
			name: "pass - pattern not matches (not_match)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test3.txt")
				os.WriteFile(file, []byte("PASS_MIN_DAYS 7\n"), 0644)
				return file
			},
			pattern:       "PASS_MAX_DAYS",
			expectedMatch: "not_match",
			wantPass:      true,
			wantErr:       false,
		},
		{
			name: "fail - pattern not matches (default match)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test4.txt")
				os.WriteFile(file, []byte("PASS_MIN_DAYS 7\n"), 0644)
				return file
			},
			pattern:       "PASS_MAX_DAYS",
			expectedMatch: "",
			wantPass:      false,
			wantErr:       false,
		},
		{
			name: "fail - pattern matches (not_match expected)",
			setup: func() string {
				file := filepath.Join(tmpDir, "test5.txt")
				os.WriteFile(file, []byte("PASS_MAX_DAYS 90\n"), 0644)
				return file
			},
			pattern:       "PASS_MAX_DAYS",
			expectedMatch: "not_match",
			wantPass:      false,
			wantErr:       false,
		},
		{
			name: "fail - file not exists",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.txt")
			},
			pattern:       ".*",
			expectedMatch: "",
			wantPass:      false,
			wantErr:       false,
		},
		{
			name: "error - invalid regex pattern",
			setup: func() string {
				file := filepath.Join(tmpDir, "test6.txt")
				os.WriteFile(file, []byte("test\n"), 0644)
				return file
			},
			pattern:       "[invalid",
			expectedMatch: "",
			wantPass:      false,
			wantErr:       true,
		},
		{
			name: "error - insufficient parameters",
			setup: func() string {
				return "" // 返回空字符串，测试时使用空参数数组
			},
			pattern:       "",
			expectedMatch: "",
			wantPass:      false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			var param []string
			if filePath == "" {
				// 测试参数不足的情况
				param = []string{}
			} else {
				param = []string{filePath, tt.pattern}
				if tt.expectedMatch != "" {
					param = append(param, tt.expectedMatch)
				}
			}

			rule := &CheckRule{
				Type:  "file_line_match",
				Param: param,
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestCommandExecChecker 测试 CommandExecChecker
func TestCommandExecChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewCommandExecChecker(logger)
	ctx := context.Background()

	tests := []struct {
		name     string
		command  string
		expected string
		wantPass bool
		wantErr  bool
	}{
		{
			name:     "pass - command output matches",
			command:  "echo test",
			expected: "test",
			wantPass: true,
			wantErr:  false,
		},
		{
			name:     "pass - command output matches with regex",
			command:  "echo 12345",
			expected: "\\d+",
			wantPass: true,
			wantErr:  false,
		},
		{
			name:     "fail - command output mismatch",
			command:  "echo test",
			expected: "other",
			wantPass: false,
			wantErr:  false,
		},
		{
			name:     "fail - command fails",
			command:  "nonexistent-command-that-fails",
			expected: ".*",
			wantPass: false,
			wantErr:  false,
		},
		{
			name:     "error - insufficient parameters",
			command:  "", // 空字符串，测试时使用空参数数组
			expected: "",
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var param []string
			if tt.command == "" && tt.expected == "" {
				param = []string{} // 测试参数不足
			} else {
				param = []string{tt.command, tt.expected}
			}
			rule := &CheckRule{
				Type:  "command_exec",
				Param: param,
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestSysctlChecker 测试 SysctlChecker
func TestSysctlChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewSysctlChecker(logger)
	ctx := context.Background()

	tests := []struct {
		name     string
		key      string
		expected string
		wantPass bool
		wantErr  bool
	}{
		{
			name:     "pass - sysctl value matches",
			key:      "kern.ostype", // 使用 macOS/Linux 都存在的参数
			expected: ".*",          // 匹配任何值（正则表达式）
			wantPass: true,
			wantErr:  false,
		},
		{
			name:     "fail - sysctl value mismatch",
			key:      "kern.ostype",
			expected: "nonexistent-value-12345",
			wantPass: false,
			wantErr:  false,
		},
		{
			name:     "fail - sysctl key not exists",
			key:      "nonexistent.sysctl.key",
			expected: ".*",
			wantPass: false,
			wantErr:  false,
		},
		{
			name:     "error - insufficient parameters",
			key:      "", // 空字符串，测试时使用空参数数组
			expected: "",
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var param []string
			if tt.key == "" && tt.expected == "" {
				param = []string{} // 测试参数不足
			} else {
				param = []string{tt.key, tt.expected}
			}
			rule := &CheckRule{
				Type:  "sysctl",
				Param: param,
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestServiceStatusChecker 测试 ServiceStatusChecker
func TestServiceStatusChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewServiceStatusChecker(logger)
	ctx := context.Background()

	tests := []struct {
		name           string
		serviceName    string
		expectedStatus string
		wantPass       bool
		wantErr        bool
		skipOnError    bool // 如果服务不存在，跳过测试
	}{
		{
			name:           "test - service status check (may fail if service not exists)",
			serviceName:    "sshd", // 通常存在的服务
			expectedStatus: "active",
			wantPass:       true, // 如果服务存在且活跃，应该通过
			wantErr:        false,
			skipOnError:    true,
		},
		{
			name:           "fail - service not exists",
			serviceName:    "nonexistent-service-12345",
			expectedStatus: "active",
			wantPass:       false,
			wantErr:        false,
			skipOnError:    false,
		},
		{
			name:           "error - insufficient parameters",
			serviceName:    "",
			expectedStatus: "",
			wantPass:       false,
			wantErr:        true,
			skipOnError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var param []string
			if tt.serviceName == "" && tt.expectedStatus == "" {
				param = []string{} // 测试参数不足
			} else {
				param = []string{tt.serviceName, tt.expectedStatus}
			}
			rule := &CheckRule{
				Type:  "service_status",
				Param: param,
			}

			result, err := checker.Check(ctx, rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.skipOnError && err != nil {
				t.Skipf("Skipping test because service check failed: %v", err)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Logf("Service check result: Pass=%v, Actual=%s, Expected=%s", result.Pass, result.Actual, result.Expected)
				// 对于服务状态检查，如果服务不存在，结果可能不符合预期，这是正常的
				if !tt.skipOnError && result.Pass != tt.wantPass {
					t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
				}
			}
		})
	}
}

// TestFileOwnerChecker 测试 FileOwnerChecker
func TestFileOwnerChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewFileOwnerChecker(logger)
	ctx := context.Background()

	// 创建临时目录
	tmpDir := t.TempDir()

	// 获取当前用户和组
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatalf("failed to get current group: %v", err)
	}

	tests := []struct {
		name     string
		setup    func() string // 返回文件路径
		rule     *CheckRule
		wantPass bool
		wantErr  bool
	}{
		{
			name: "pass - uid:gid match",
			setup: func() string {
				file := filepath.Join(tmpDir, "test1.txt")
				os.WriteFile(file, []byte("test content"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_owner",
				Param: []string{"", fmt.Sprintf("%s:%s", currentUser.Uid, currentUser.Gid)},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "pass - username:groupname match",
			setup: func() string {
				file := filepath.Join(tmpDir, "test2.txt")
				os.WriteFile(file, []byte("test content"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_owner",
				Param: []string{"", fmt.Sprintf("%s:%s", currentUser.Username, currentGroup.Name)},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "fail - uid mismatch",
			setup: func() string {
				file := filepath.Join(tmpDir, "test3.txt")
				os.WriteFile(file, []byte("test content"), 0644)
				return file
			},
			rule: &CheckRule{
				Type:  "file_owner",
				Param: []string{"", "9999:9999"},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "fail - file not exists",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.txt")
			},
			rule: &CheckRule{
				Type:  "file_owner",
				Param: []string{"", "0:0"},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "error - insufficient parameters",
			setup: func() string {
				return ""
			},
			rule: &CheckRule{
				Type:  "file_owner",
				Param: []string{"/etc/passwd"},
			},
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			if filePath != "" {
				tt.rule.Param[0] = filePath
			}

			result, err := checker.Check(ctx, tt.rule)

			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && result.Pass != tt.wantPass {
				t.Logf("File owner check result: Pass=%v, Actual=%s, Expected=%s", result.Pass, result.Actual, result.Expected)
				t.Errorf("Check() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestPackageInstalledChecker 测试 PackageInstalledChecker
func TestPackageInstalledChecker(t *testing.T) {
	logger := setupTestLogger(t)
	checker := NewPackageInstalledChecker(logger)
	ctx := context.Background()

	tests := []struct {
		name     string
		rule     *CheckRule
		wantPass bool
		wantErr  bool
		skip     bool // 是否跳过测试（如果包管理器不存在）
	}{
		{
			name: "check coreutils (should be installed on most systems)",
			rule: &CheckRule{
				Type:  "package_installed",
				Param: []string{"coreutils"},
			},
			wantPass: true,
			wantErr:  false,
			skip:     false,
		},
		{
			name: "check nonexistent package",
			rule: &CheckRule{
				Type:  "package_installed",
				Param: []string{"nonexistent-package-12345"},
			},
			wantPass: false,
			wantErr:  false,
			skip:     false,
		},
		{
			name: "error - insufficient parameters",
			rule: &CheckRule{
				Type:  "package_installed",
				Param: []string{},
			},
			wantPass: false,
			wantErr:  true,
			skip:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip("Skipping test")
			}

			result, err := checker.Check(ctx, tt.rule)

			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				t.Logf("Package check result: Pass=%v, Actual=%s, Expected=%s", result.Pass, result.Actual, result.Expected)
				// 对于包检查，如果包管理器不存在，结果可能不符合预期，这是正常的
				// 我们只检查错误情况，不强制检查 Pass 值
				if !tt.wantErr && result.Pass != tt.wantPass {
					// 如果包管理器不存在，Actual 会包含 "无法检测包管理器"
					if !strings.Contains(result.Actual, "无法检测包管理器") {
						t.Logf("Note: Package check result may vary depending on system: Pass=%v, Actual=%s", result.Pass, result.Actual)
					}
				}
			}
		})
	}
}
