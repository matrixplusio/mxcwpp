package plugin

import "testing"

func TestWithArchParam(t *testing.T) {
	for _, c := range []struct{ in, arch, want string }{
		{"https://cwpp.example/api/v1/plugins/download/collector", "arm64", "https://cwpp.example/api/v1/plugins/download/collector?arch=arm64"},
		{"https://cwpp.example/api/v1/plugins/download/collector", "amd64", "https://cwpp.example/api/v1/plugins/download/collector?arch=amd64"},
		// 已带架构：不覆盖
		{"https://cwpp.example/api/v1/plugins/download/fim?arch=amd64", "arm64", "https://cwpp.example/api/v1/plugins/download/fim?arch=amd64"},
		// 已有其他参数：保留并追加
		{"https://cwpp.example/api/v1/plugins/download/fim?v=1", "arm64", "https://cwpp.example/api/v1/plugins/download/fim?arch=arm64&v=1"},
		// 外部地址：不动，避免破坏签名
		{"https://bucket.example/collector?X-Sig=abc", "arm64", "https://bucket.example/collector?X-Sig=abc"},
	} {
		if got := withArchParam(c.in, c.arch); got != c.want {
			t.Errorf("withArchParam(%q, %q) = %q，期望 %q", c.in, c.arch, got, c.want)
		}
	}
}
