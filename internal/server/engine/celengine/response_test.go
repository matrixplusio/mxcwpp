package celengine

import (
	"testing"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"go.uber.org/zap"
)

// mockDispatcher 模拟命令分发器
type mockDispatcher struct {
	commands []dispatchedCmd
	failFor  map[string]bool // agentID → 是否返回错误
}

type dispatchedCmd struct {
	agentID string
	cmd     interface{}
}

func (m *mockDispatcher) SendCommand(agentID string, cmd interface{}) error {
	m.commands = append(m.commands, dispatchedCmd{agentID: agentID, cmd: cmd})
	if m.failFor != nil && m.failFor[agentID] {
		return errMockDispatch
	}
	return nil
}

var errMockDispatch = &mockError{"dispatch failed"}

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }

// TestAutoResponder_CriticalRuleTriggers 测试 critical 规则触发自动响应
func TestAutoResponder_CriticalRuleTriggers(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	disp := &mockDispatcher{}
	ar.SetDispatcher(disp)

	rules := []model.DetectionRule{
		{Name: "反弹Shell", Severity: "critical"},
	}
	fields := map[string]string{
		"pid":       "12345",
		"file_path": "/tmp/evil.sh",
		"remote_ip": "10.0.0.99",
	}

	ar.Execute("agent-001", rules, fields)

	// critical 规则 + 3 个字段 → 应生成 3 个命令：kill_process, quarantine_file, block_ip
	if len(disp.commands) != 3 {
		t.Fatalf("期望 3 个命令，实际 %d", len(disp.commands))
	}

	// 验证所有命令目标是 agent-001
	for _, cmd := range disp.commands {
		if cmd.agentID != "agent-001" {
			t.Errorf("命令目标 agentID = %s, want agent-001", cmd.agentID)
		}
	}

	// 验证 data_type
	expectedTypes := []int{9998, 7003, 9997} // kill, quarantine, block
	for i, cmd := range disp.commands {
		cmdMap, ok := cmd.cmd.(map[string]interface{})
		if !ok {
			t.Fatalf("命令 %d 类型错误: %T", i, cmd.cmd)
		}
		dt, ok := cmdMap["data_type"]
		if !ok {
			t.Fatalf("命令 %d 缺少 data_type", i)
		}
		if int(dt.(int)) != expectedTypes[i] {
			t.Errorf("命令 %d data_type = %v, want %d", i, dt, expectedTypes[i])
		}
	}
}

// TestAutoResponder_NonCriticalSkipped 测试非 critical 规则不触发自动响应
func TestAutoResponder_NonCriticalSkipped(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	disp := &mockDispatcher{}
	ar.SetDispatcher(disp)

	severities := []string{"high", "medium", "low", "info"}
	for _, sev := range severities {
		rules := []model.DetectionRule{
			{Name: "测试规则", Severity: sev},
		}
		fields := map[string]string{
			"pid": "12345",
		}
		ar.Execute("agent-001", rules, fields)
	}

	if len(disp.commands) != 0 {
		t.Errorf("非 critical 规则不应触发自动响应，实际命令数 = %d", len(disp.commands))
	}
}

// TestAutoResponder_NilDispatcherSafe 测试 dispatcher 为 nil 时不 panic
func TestAutoResponder_NilDispatcherSafe(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	// 不调用 SetDispatcher，dispatcher 为 nil

	rules := []model.DetectionRule{
		{Name: "测试", Severity: "critical"},
	}
	fields := map[string]string{"pid": "12345"}

	// 不应 panic
	ar.Execute("agent-001", rules, fields)
}

// TestAutoResponder_DispatcherFailGraceful 测试分发失败时优雅降级
func TestAutoResponder_DispatcherFailGraceful(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	disp := &mockDispatcher{
		failFor: map[string]bool{"agent-002": true},
	}
	ar.SetDispatcher(disp)

	rules := []model.DetectionRule{
		{Name: "测试", Severity: "critical"},
	}
	fields := map[string]string{"pid": "12345"}

	// 不应 panic，即使分发失败
	ar.Execute("agent-002", rules, fields)

	// 应尝试发送命令
	if len(disp.commands) != 1 {
		t.Errorf("期望 1 个命令尝试，实际 %d", len(disp.commands))
	}
}

// TestAutoResponder_PartialFields 测试部分字段时只生成对应的动作
func TestAutoResponder_PartialFields(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	disp := &mockDispatcher{}
	ar.SetDispatcher(disp)

	tests := []struct {
		name     string
		fields   map[string]string
		wantCmds int
	}{
		{"仅 pid", map[string]string{"pid": "123"}, 1},
		{"仅 file_path", map[string]string{"file_path": "/tmp/x"}, 1},
		{"仅 remote_ip", map[string]string{"remote_ip": "1.2.3.4"}, 1},
		{"pid + remote_ip", map[string]string{"pid": "123", "remote_ip": "1.2.3.4"}, 2},
		{"无可响应字段", map[string]string{"hostname": "web01"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disp.commands = nil
			rules := []model.DetectionRule{
				{Name: "测试", Severity: "critical"},
			}
			ar.Execute("agent-001", rules, tt.fields)
			if len(disp.commands) != tt.wantCmds {
				t.Errorf("期望 %d 个命令，实际 %d", tt.wantCmds, len(disp.commands))
			}
		})
	}
}

// TestAutoResponder_MultipleRules 测试多规则匹配时分别执行
func TestAutoResponder_MultipleRules(t *testing.T) {
	logger := zap.NewNop()
	ar := NewAutoResponder(nil, logger)
	disp := &mockDispatcher{}
	ar.SetDispatcher(disp)

	rules := []model.DetectionRule{
		{Name: "规则1", Severity: "critical"},
		{Name: "规则2", Severity: "high"},     // 不触发
		{Name: "规则3", Severity: "critical"}, // 触发
	}
	fields := map[string]string{"pid": "123"}

	ar.Execute("agent-001", rules, fields)

	// 2 个 critical 规则 × 1 个字段 = 2 个命令
	if len(disp.commands) != 2 {
		t.Errorf("期望 2 个命令，实际 %d", len(disp.commands))
	}
}
