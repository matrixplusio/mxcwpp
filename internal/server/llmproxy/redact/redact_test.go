package redact

import "testing"

func TestRedact_IPAndHost(t *testing.T) {
	d := New([]string{"mxcorp.io"})
	cases := []struct {
		in   string
		want string
	}{
		{"主机 10.0.3.21 异常", "主机 [REDACTED_IP] 异常"},
		{"连到 192.168.1.1:8080", "连到 [REDACTED_IP]:8080"},
		{"node web-01.cluster.local down", "node [REDACTED_HOST] down"},
		{"target db.mxcorp.io", "target [REDACTED_HOST]"},
		{"无敏感信息的普通文本", "无敏感信息的普通文本"},
	}
	for _, c := range cases {
		if got := d.Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsLocalURL(t *testing.T) {
	local := []string{
		"http://localhost:11434/v1",
		"http://127.0.0.1:11434",
		"http://10.0.0.5:8000/v1",
		"http://ollama.internal/v1",
	}
	external := []string{
		"https://api.openai.com/v1",
		"https://dashscope.aliyuncs.com/compatible-mode/v1",
		"https://api.anthropic.com",
	}
	for _, u := range local {
		if !IsLocalURL(u) {
			t.Errorf("IsLocalURL(%q) = false, want true", u)
		}
	}
	for _, u := range external {
		if IsLocalURL(u) {
			t.Errorf("IsLocalURL(%q) = true, want false", u)
		}
	}
}
