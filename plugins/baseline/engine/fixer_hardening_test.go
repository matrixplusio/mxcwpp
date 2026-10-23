package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// 构造一条规则：check 用 file_line_match 判定 file 是否含 "COMPLIANT"。
func ruleCheckingFile(file, fixCmd string, restart []string) (*Policy, *Rule) {
	rule := &Rule{
		RuleID: "TEST_FIX_001",
		Title:  "test",
		Check: &Check{
			Condition: "all",
			Rules: []*CheckRule{
				{Type: "file_line_match", Param: []string{file, "COMPLIANT", "match"}},
			},
		},
		Fix: &Fix{Command: fixCmd, RestartServices: restart},
	}
	return &Policy{ID: "TEST_POLICY", Rules: []*Rule{rule}}, rule
}

// P1：修后复检——命令"成功"但未真正合规时，状态应为 failed 而非 success。
func TestFixer_PostVerify_CatchesFalseSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	tmp := t.TempDir()

	t.Run("real fix verified pass -> success", func(t *testing.T) {
		file := filepath.Join(tmp, "real.conf")
		_ = os.WriteFile(file, []byte("OTHER\n"), 0644)
		// fix 真把 COMPLIANT 写进文件
		policy, rule := ruleCheckingFile(file, "echo COMPLIANT >> "+file, nil)
		f := NewFixer(logger)
		f.SetVerifier(NewEngine(logger))
		res := f.Fix(ctx, policy, rule)
		if res.Status != FixStatusSuccess {
			t.Fatalf("got %s, want success (msg=%s)", res.Status, res.Message)
		}
	})

	t.Run("no-op fix verified fail -> failed (false success caught)", func(t *testing.T) {
		file := filepath.Join(tmp, "noop.conf")
		_ = os.WriteFile(file, []byte("OTHER\n"), 0644)
		// fix 命令退出 0 但什么都没改 → 复检仍 fail
		policy, rule := ruleCheckingFile(file, "true", nil)
		f := NewFixer(logger)
		f.SetVerifier(NewEngine(logger))
		res := f.Fix(ctx, policy, rule)
		if res.Status != FixStatusFailed {
			t.Fatalf("got %s, want failed — false success not caught (msg=%s)", res.Status, res.Message)
		}
	})

	t.Run("no verifier -> stays success (backward compat)", func(t *testing.T) {
		file := filepath.Join(tmp, "compat.conf")
		_ = os.WriteFile(file, []byte("OTHER\n"), 0644)
		policy, rule := ruleCheckingFile(file, "true", nil)
		f := NewFixer(logger) // 不注入 verifier
		res := f.Fix(ctx, policy, rule)
		if res.Status != FixStatusSuccess {
			t.Fatalf("got %s, want success (no verifier = 不阻断)", res.Status)
		}
	})
}

// P2：服务重启前配置校验失败时，跳过重启并判 failed。
func TestFixer_PreRestartValidation_SkipsOnInvalidConfig(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	tmp := t.TempDir()

	// 注入一个必失败的校验器，测试结束清理。
	serviceValidators["testsvc"] = "false"
	defer delete(serviceValidators, "testsvc")

	file := filepath.Join(tmp, "svc.conf")
	_ = os.WriteFile(file, []byte("COMPLIANT\n"), 0644)
	policy, rule := ruleCheckingFile(file, "true", []string{"testsvc"})

	f := NewFixer(logger)
	f.SetVerifier(NewEngine(logger))
	res := f.Fix(ctx, policy, rule)

	if res.Status != FixStatusFailed {
		t.Fatalf("got %s, want failed (校验失败应跳过重启并判失败)", res.Status)
	}
	if res.ErrorMsg == "" {
		t.Errorf("want non-empty error_msg describing validation failure")
	}
}
