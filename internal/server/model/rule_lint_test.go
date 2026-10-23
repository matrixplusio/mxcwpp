package model

import "testing"

func TestLintRuleExpression(t *testing.T) {
	for _, bad := range []string{
		`exe.contains("w")`,
		`exe.contains("nc") && cmdline.contains("-e")`,
		`x || exe.contains("id")`,
		`parent_exe.contains("sh")`, // 父进程路径同理：sh 会命中 bash、zsh、sshd
	} {
		if LintRuleExpression(bad) == "" {
			t.Errorf("应拦下: %s", bad)
		}
	}
	for _, ok := range []string{
		`(exe == "nc" || exe.endsWith("/nc"))`,
		`exe.contains("ncat")`,
		`cmdline.contains("-e")`,
	} {
		if msg := LintRuleExpression(ok); msg != "" {
			t.Errorf("不应拦下 %s: %s", ok, msg)
		}
	}
}
