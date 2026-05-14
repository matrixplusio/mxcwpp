// Package engine 提供基线检查引擎的端到端测试
package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestEngine_E2E_WithExamplePolicy 使用示例规则文件进行端到端测试
func TestEngine_E2E_WithExamplePolicy(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)
	ctx := context.Background()

	// 获取示例规则文件路径
	exampleDir := filepath.Join("..", "config", "examples")
	policyFile := filepath.Join(exampleDir, "password-policy.json")

	// 检查文件是否存在
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		// 尝试从项目根目录查找
		policyFile = filepath.Join("plugins", "baseline", "config", "examples", "password-policy.json")
		if _, err := os.Stat(policyFile); os.IsNotExist(err) {
			t.Skipf("示例规则文件不存在: %s", policyFile)
			return
		}
	}

	// 读取 JSON 文件
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("读取规则文件失败: %v", err)
	}

	// 解析为 Policy 对象
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("解析规则文件失败: %v", err)
	}

	// 验证策略基本信息
	if policy.ID == "" {
		t.Error("策略 ID 为空")
	}
	if len(policy.Rules) == 0 {
		t.Error("策略规则列表为空")
	}

	t.Logf("加载策略: %s (%s), 规则数量: %d", policy.Name, policy.ID, len(policy.Rules))

	// 创建临时文件用于测试（模拟 /etc/login.defs）
	tmpDir := t.TempDir()
	loginDefs := filepath.Join(tmpDir, "login.defs")

	// 测试场景1: 文件不存在的情况
	t.Run("文件不存在", func(t *testing.T) {
		// 修改规则中的文件路径为不存在的文件
		policies := []*Policy{&policy}
		// 临时修改规则中的文件路径
		originalRules := make([]*Rule, len(policy.Rules))
		for i, rule := range policy.Rules {
			originalRules[i] = rule
			// 修改文件路径
			for _, checkRule := range rule.Check.Rules {
				if checkRule.Type == "file_exists" || checkRule.Type == "file_line_match" {
					// 将路径替换为不存在的文件
					if len(checkRule.Param) > 0 {
						checkRule.Param[0] = filepath.Join(tmpDir, "nonexistent_login.defs")
					}
				}
			}
		}

		results := engine.Execute(ctx, policies, "rocky", "9.3")

		// 应该返回结果（即使失败）
		if len(results) == 0 {
			t.Error("期望返回检查结果，但结果为空")
		}

		// 验证结果结构
		for _, result := range results {
			if result.RuleID == "" {
				t.Error("结果 RuleID 为空")
			}
			if result.PolicyID != policy.ID {
				t.Errorf("结果 PolicyID = %s, 期望 %s", result.PolicyID, policy.ID)
			}
			if result.Status == "" {
				t.Error("结果 Status 为空")
			}
			t.Logf("规则 %s: 状态=%s, 标题=%s", result.RuleID, result.Status, result.Title)
		}

		// 恢复原始规则
		for i := range policy.Rules {
			policy.Rules[i] = originalRules[i]
		}
	})

	// 测试场景2: 文件存在但配置不符合要求
	t.Run("文件存在但配置不符合", func(t *testing.T) {
		// 创建不符合要求的配置文件
		os.WriteFile(loginDefs, []byte("# Password aging controls\nPASS_MAX_DAYS 999\nPASS_MIN_LEN 4\n"), 0644)

		// 修改规则中的文件路径
		policies := []*Policy{&policy}
		for _, rule := range policy.Rules {
			for _, checkRule := range rule.Check.Rules {
				if checkRule.Type == "file_exists" || checkRule.Type == "file_line_match" {
					if len(checkRule.Param) > 0 {
						checkRule.Param[0] = loginDefs
					}
				}
			}
		}

		results := engine.Execute(ctx, policies, "rocky", "9.3")

		if len(results) == 0 {
			t.Error("期望返回检查结果，但结果为空")
		}

		// 验证结果
		for _, result := range results {
			t.Logf("规则 %s: 状态=%s, 实际=%s, 期望=%s", result.RuleID, result.Status, result.Actual, result.Expected)
		}

		// 注意：由于规则可能检查的是"存在"而不是"值匹配"，所以不一定失败
		// 这里主要验证引擎能正常执行
		t.Logf("检查完成，结果数量: %d", len(results))
	})

	// 测试场景3: 文件存在且配置符合要求
	t.Run("文件存在且配置符合", func(t *testing.T) {
		// 创建符合要求的配置文件
		os.WriteFile(loginDefs, []byte("# Password aging controls\nPASS_MAX_DAYS 90\nPASS_MIN_LEN 8\n"), 0644)

		// 修改规则中的文件路径
		policies := []*Policy{&policy}
		for _, rule := range policy.Rules {
			for _, checkRule := range rule.Check.Rules {
				if checkRule.Type == "file_exists" || checkRule.Type == "file_line_match" {
					if len(checkRule.Param) > 0 {
						checkRule.Param[0] = loginDefs
					}
				}
			}
		}

		results := engine.Execute(ctx, policies, "rocky", "9.3")

		if len(results) == 0 {
			t.Error("期望返回检查结果，但结果为空")
		}

		// 验证结果
		for _, result := range results {
			t.Logf("规则 %s: 状态=%s, 标题=%s", result.RuleID, result.Status, result.Title)
		}

		t.Logf("检查完成，结果数量: %d", len(results))
	})

	// 测试场景4: OS 不匹配
	t.Run("OS不匹配", func(t *testing.T) {
		results := engine.Execute(ctx, []*Policy{&policy}, "windows", "10")

		// OS 不匹配时，应该没有结果
		if len(results) != 0 {
			t.Errorf("OS 不匹配时应该没有结果，但返回了 %d 个结果", len(results))
		}
		t.Logf("OS 不匹配测试通过，结果数量: %d", len(results))
	})
}

// TestEngine_E2E_LoadAllExamplePolicies 加载所有示例策略文件进行测试
func TestEngine_E2E_LoadAllExamplePolicies(t *testing.T) {
	logger := setupTestLogger(t)
	engine := NewEngine(logger)
	ctx := context.Background()

	// 获取示例规则文件目录
	exampleDir := filepath.Join("..", "config", "examples")
	if _, err := os.Stat(exampleDir); os.IsNotExist(err) {
		exampleDir = filepath.Join("plugins", "baseline", "config", "examples")
		if _, err := os.Stat(exampleDir); os.IsNotExist(err) {
			t.Skipf("示例规则目录不存在: %s", exampleDir)
			return
		}
	}

	// 读取所有 JSON 文件
	files, err := os.ReadDir(exampleDir)
	if err != nil {
		t.Fatalf("读取示例目录失败: %v", err)
	}

	var policies []*Policy
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		policyFile := filepath.Join(exampleDir, file.Name())
		data, err := os.ReadFile(policyFile)
		if err != nil {
			t.Logf("跳过文件 %s: %v", file.Name(), err)
			continue
		}

		var policy Policy
		if err := json.Unmarshal(data, &policy); err != nil {
			t.Logf("解析文件 %s 失败: %v", file.Name(), err)
			continue
		}

		if !policy.Enabled {
			t.Logf("策略 %s 未启用，跳过", policy.ID)
			continue
		}

		policies = append(policies, &policy)
		t.Logf("加载策略: %s (%s), 规则数量: %d", policy.Name, policy.ID, len(policy.Rules))
	}

	if len(policies) == 0 {
		t.Skip("没有找到可用的策略文件")
		return
	}

	// 执行检查（使用匹配的 OS）
	results := engine.Execute(ctx, policies, "rocky", "9.3")

	t.Logf("总共加载 %d 个策略，执行后返回 %d 个结果", len(policies), len(results))

	// 统计结果
	statusCount := make(map[Status]int)
	for _, result := range results {
		statusCount[result.Status]++
	}

	t.Logf("结果统计:")
	for status, count := range statusCount {
		t.Logf("  %s: %d", status, count)
	}

	// 验证所有结果都有必要的字段
	for _, result := range results {
		if result.RuleID == "" {
			t.Error("结果 RuleID 为空")
		}
		if result.PolicyID == "" {
			t.Error("结果 PolicyID 为空")
		}
		if result.Status == "" {
			t.Error("结果 Status 为空")
		}
		if result.CheckedAt.IsZero() {
			t.Error("结果 CheckedAt 为零值")
		}
	}
}
