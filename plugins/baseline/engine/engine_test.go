// Package engine 提供基线检查引擎的单元测试
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestEngine_Execute 测试 Engine.Execute
func TestEngine_Execute(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()

	// 创建测试文件
	testFile := filepath.Join(tmpDir, "test.conf")
	os.WriteFile(testFile, []byte("PermitRootLogin no\nPort 22\n"), 0644)

	tests := []struct {
		name            string
		policies        []*Policy
		osFamily        string
		osVersion       string
		wantResultCount int
	}{
		{
			name: "pass - policy matches OS",
			policies: []*Policy{
				{
					ID:          "TEST_POLICY_1",
					Name:        "Test Policy 1",
					Version:     "1.0.0",
					Description: "Test",
					OSFamily:    []string{"rocky"},
					OSVersion:   ">=9",
					Enabled:     true,
					Rules: []*Rule{
						{
							RuleID:      "TEST_RULE_1",
							Category:    "test",
							Title:       "Test Rule 1",
							Description: "Test",
							Severity:    "high",
							Check: &Check{
								Condition: "all",
								Rules: []*CheckRule{
									{
										Type:  "file_exists",
										Param: []string{testFile},
									},
									{
										Type:  "file_kv",
										Param: []string{testFile, "PermitRootLogin", "no"},
									},
								},
							},
							Fix: &Fix{
								Suggestion: "Fix suggestion",
							},
						},
					},
				},
			},
			osFamily:        "rocky",
			osVersion:       "9.3",
			wantResultCount: 1,
		},
		{
			name: "skip - policy OS family mismatch",
			policies: []*Policy{
				{
					ID:          "TEST_POLICY_2",
					Name:        "Test Policy 2",
					Version:     "1.0.0",
					Description: "Test",
					OSFamily:    []string{"debian"},
					OSVersion:   ">=10",
					Enabled:     true,
					Rules: []*Rule{
						{
							RuleID:      "TEST_RULE_2",
							Category:    "test",
							Title:       "Test Rule 2",
							Description: "Test",
							Severity:    "high",
							Check: &Check{
								Condition: "all",
								Rules: []*CheckRule{
									{
										Type:  "file_exists",
										Param: []string{testFile},
									},
								},
							},
							Fix: &Fix{
								Suggestion: "Fix suggestion",
							},
						},
					},
				},
			},
			osFamily:        "rocky",
			osVersion:       "9.3",
			wantResultCount: 0,
		},
		{
			name: "skip - policy OS version mismatch",
			policies: []*Policy{
				{
					ID:          "TEST_POLICY_3",
					Name:        "Test Policy 3",
					Version:     "1.0.0",
					Description: "Test",
					OSFamily:    []string{"rocky"},
					OSVersion:   ">=10",
					Enabled:     true,
					Rules: []*Rule{
						{
							RuleID:      "TEST_RULE_3",
							Category:    "test",
							Title:       "Test Rule 3",
							Description: "Test",
							Severity:    "high",
							Check: &Check{
								Condition: "all",
								Rules: []*CheckRule{
									{
										Type:  "file_exists",
										Param: []string{testFile},
									},
								},
							},
							Fix: &Fix{
								Suggestion: "Fix suggestion",
							},
						},
					},
				},
			},
			osFamily:        "rocky",
			osVersion:       "9.3",
			wantResultCount: 0,
		},
		{
			name: "multiple rules in one policy",
			policies: []*Policy{
				{
					ID:          "TEST_POLICY_4",
					Name:        "Test Policy 4",
					Version:     "1.0.0",
					Description: "Test",
					OSFamily:    []string{"rocky"},
					OSVersion:   ">=9",
					Enabled:     true,
					Rules: []*Rule{
						{
							RuleID:      "TEST_RULE_4A",
							Category:    "test",
							Title:       "Test Rule 4A",
							Description: "Test",
							Severity:    "high",
							Check: &Check{
								Condition: "all",
								Rules: []*CheckRule{
									{
										Type:  "file_exists",
										Param: []string{testFile},
									},
								},
							},
							Fix: &Fix{
								Suggestion: "Fix suggestion",
							},
						},
						{
							RuleID:      "TEST_RULE_4B",
							Category:    "test",
							Title:       "Test Rule 4B",
							Description: "Test",
							Severity:    "medium",
							Check: &Check{
								Condition: "all",
								Rules: []*CheckRule{
									{
										Type:  "file_kv",
										Param: []string{testFile, "Port", "22"},
									},
								},
							},
							Fix: &Fix{
								Suggestion: "Fix suggestion",
							},
						},
					},
				},
			},
			osFamily:        "rocky",
			osVersion:       "9.3",
			wantResultCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := engine.Execute(ctx, tt.policies, tt.osFamily, tt.osVersion)
			if len(results) != tt.wantResultCount {
				t.Errorf("Execute() result count = %d, want %d", len(results), tt.wantResultCount)
			}

			// 验证结果结构
			for _, result := range results {
				if result.RuleID == "" {
					t.Error("Result RuleID is empty")
				}
				if result.PolicyID == "" {
					t.Error("Result PolicyID is empty")
				}
				if result.Status == "" {
					t.Error("Result Status is empty")
				}
				if result.CheckedAt.IsZero() {
					t.Error("Result CheckedAt is zero")
				}
			}
		})
	}
}

// TestEngine_executeCheck 测试条件组合
func TestEngine_executeCheck(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.conf")
	os.WriteFile(testFile, []byte("PermitRootLogin no\nPort 22\n"), 0644)

	tests := []struct {
		name     string
		check    *Check
		wantPass bool
		wantErr  bool
	}{
		{
			name: "condition all - all pass",
			check: &Check{
				Condition: "all",
				Rules: []*CheckRule{
					{
						Type:  "file_exists",
						Param: []string{testFile},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "no"},
					},
				},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "condition all - one fail",
			check: &Check{
				Condition: "all",
				Rules: []*CheckRule{
					{
						Type:  "file_exists",
						Param: []string{testFile},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "yes"},
					},
				},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "condition any - one pass",
			check: &Check{
				Condition: "any",
				Rules: []*CheckRule{
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "yes"},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "Port", "22"},
					},
				},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "condition any - all fail",
			check: &Check{
				Condition: "any",
				Rules: []*CheckRule{
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "yes"},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "Port", "8080"},
					},
				},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "condition none - all fail",
			check: &Check{
				Condition: "none",
				Rules: []*CheckRule{
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "yes"},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "Port", "8080"},
					},
				},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "condition none - one pass",
			check: &Check{
				Condition: "none",
				Rules: []*CheckRule{
					{
						Type:  "file_kv",
						Param: []string{testFile, "PermitRootLogin", "no"},
					},
					{
						Type:  "file_kv",
						Param: []string{testFile, "Port", "8080"},
					},
				},
			},
			wantPass: false,
			wantErr:  false,
		},
		{
			name: "default condition - single check",
			check: &Check{
				Condition: "",
				Rules: []*CheckRule{
					{
						Type:  "file_exists",
						Param: []string{testFile},
					},
				},
			},
			wantPass: true,
			wantErr:  false,
		},
		{
			name: "error - unknown check type",
			check: &Check{
				Condition: "all",
				Rules: []*CheckRule{
					{
						Type:  "unknown_check_type",
						Param: []string{},
					},
				},
			},
			wantPass: false,
			wantErr:  true,
		},
		{
			name: "error - no check rules",
			check: &Check{
				Condition: "all",
				Rules:     []*CheckRule{},
			},
			wantPass: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.executeCheck(ctx, tt.check)
			if (err != nil) != tt.wantErr {
				t.Errorf("executeCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result.Pass != tt.wantPass {
				t.Errorf("executeCheck() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

// TestPolicy_MatchOS 测试 OS 匹配逻辑
func TestPolicy_MatchOS(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		osFamily  string
		osVersion string
		want      bool
	}{
		{
			name: "pass - OS family matches",
			policy: &Policy{
				OSFamily:  []string{"rocky", "centos"},
				OSVersion: ">=9",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "pass - OS family matches (case insensitive)",
			policy: &Policy{
				OSFamily:  []string{"Rocky", "CentOS"},
				OSVersion: ">=9",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "fail - OS family mismatch",
			policy: &Policy{
				OSFamily:  []string{"debian", "ubuntu"},
				OSVersion: ">=10",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      false,
		},
		{
			name: "fail - OS version too low",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: ">=10",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      false,
		},
		{
			name: "pass - OS version matches (>=)",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: ">=9",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "pass - OS version matches (exact)",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: "9.3",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "pass - no version constraint",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: "",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "pass - version constraint with >",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: ">9",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      true,
		},
		{
			name: "fail - version constraint with >",
			policy: &Policy{
				OSFamily:  []string{"rocky"},
				OSVersion: ">9.3",
			},
			osFamily:  "rocky",
			osVersion: "9.3",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.MatchOS(tt.osFamily, tt.osVersion)
			if got != tt.want {
				t.Errorf("MatchOS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEngine_executeRule 测试规则执行
func TestEngine_executeRule(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)
	ctx := context.Background()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.conf")
	os.WriteFile(testFile, []byte("PermitRootLogin no\n"), 0644)

	policy := &Policy{
		ID:          "TEST_POLICY",
		Name:        "Test Policy",
		Version:     "1.0.0",
		Description: "Test",
		OSFamily:    []string{"rocky"},
		OSVersion:   ">=9",
		Enabled:     true,
	}

	tests := []struct {
		name       string
		rule       *Rule
		wantStatus Status
	}{
		{
			name: "pass - check passes",
			rule: &Rule{
				RuleID:      "TEST_RULE_PASS",
				Category:    "test",
				Title:       "Test Rule Pass",
				Description: "Test",
				Severity:    "high",
				Check: &Check{
					Condition: "all",
					Rules: []*CheckRule{
						{
							Type:  "file_exists",
							Param: []string{testFile},
						},
						{
							Type:  "file_kv",
							Param: []string{testFile, "PermitRootLogin", "no"},
						},
					},
				},
				Fix: &Fix{
					Suggestion: "Fix suggestion",
				},
			},
			wantStatus: StatusPass,
		},
		{
			name: "fail - check fails",
			rule: &Rule{
				RuleID:      "TEST_RULE_FAIL",
				Category:    "test",
				Title:       "Test Rule Fail",
				Description: "Test",
				Severity:    "high",
				Check: &Check{
					Condition: "all",
					Rules: []*CheckRule{
						{
							Type:  "file_kv",
							Param: []string{testFile, "PermitRootLogin", "yes"},
						},
					},
				},
				Fix: &Fix{
					Suggestion: "Fix suggestion",
				},
			},
			wantStatus: StatusFail,
		},
		{
			name: "error - check error",
			rule: &Rule{
				RuleID:      "TEST_RULE_ERROR",
				Category:    "test",
				Title:       "Test Rule Error",
				Description: "Test",
				Severity:    "high",
				Check: &Check{
					Condition: "all",
					Rules: []*CheckRule{
						{
							Type:  "unknown_check_type",
							Param: []string{},
						},
					},
				},
				Fix: &Fix{
					Suggestion: "Fix suggestion",
				},
			},
			wantStatus: StatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.executeRule(ctx, policy, tt.rule)
			if result == nil {
				t.Fatal("executeRule() returned nil")
			}
			if result.Status != tt.wantStatus {
				t.Errorf("executeRule() Status = %v, want %v", result.Status, tt.wantStatus)
			}
			if result.RuleID != tt.rule.RuleID {
				t.Errorf("executeRule() RuleID = %v, want %v", result.RuleID, tt.rule.RuleID)
			}
			if result.PolicyID != policy.ID {
				t.Errorf("executeRule() PolicyID = %v, want %v", result.PolicyID, policy.ID)
			}
			if result.FixSuggestion != tt.rule.Fix.Suggestion {
				t.Errorf("executeRule() FixSuggestion = %v, want %v", result.FixSuggestion, tt.rule.Fix.Suggestion)
			}
			if result.CheckedAt.IsZero() {
				t.Error("executeRule() CheckedAt is zero")
			}
		})
	}
}

// TestEngine_RegisterChecker 测试检查器注册
func TestEngine_RegisterChecker(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)

	// 创建自定义检查器
	customChecker := &mockChecker{pass: true}
	engine.RegisterChecker("custom_checker", customChecker)

	// 验证检查器已注册
	ctx := context.Background()
	rule := &CheckRule{
		Type:  "custom_checker",
		Param: []string{},
	}

	result, err := engine.executeSingleCheck(ctx, rule)
	if err != nil {
		t.Fatalf("executeSingleCheck() error = %v", err)
	}
	if !result.Pass {
		t.Error("Custom checker should pass")
	}
}

// mockChecker 是用于测试的模拟检查器
type mockChecker struct {
	pass bool
}

func (m *mockChecker) Check(ctx context.Context, rule *CheckRule) (*CheckResult, error) {
	return &CheckResult{
		Pass:     m.pass,
		Actual:   "mock actual",
		Expected: "mock expected",
	}, nil
}
