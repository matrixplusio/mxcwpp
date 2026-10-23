package model

import "testing"

// 原生审计日志的 sourceIPs 前几项来自 X-Forwarded-For，请求方可以随意填写。
func TestDirectSourceIP(t *testing.T) {
	e := AuditEvent{SourceIPs: []string{"6.6.6.6", "10.0.0.1", "203.0.113.9"}}
	if got := e.DirectSourceIP(); got != "203.0.113.9" {
		t.Errorf("应取最后一项（API Server 看到的对端）：%q", got)
	}
	if got := (&AuditEvent{}).DirectSourceIP(); got != "" {
		t.Errorf("没有来源时应为空：%q", got)
	}
}
