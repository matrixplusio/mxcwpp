package main

import "testing"

// TestResolveTrustConfig 环境变量必须覆盖构建期嵌入值。
//
// 取值顺序搞反的后果不是报错而是静默失败：安装脚本按机注入的令牌被旧的嵌入值盖掉，
// 全网新装 agent 一律 enroll 被拒，且现场看起来只是"连不上"。
func TestResolveTrustConfig(t *testing.T) {
	cases := []struct {
		name                string
		envFP, envToken     string
		embedFP, embedToken string
		wantFP, wantToken   string
	}{
		{"全空", "", "", "", "", "", ""},
		{"仅嵌入值", "", "", "fp-embed", "tok-embed", "fp-embed", "tok-embed"},
		{"仅环境变量", "fp-env", "tok-env", "", "", "fp-env", "tok-env"},
		{"环境变量覆盖嵌入值", "fp-env", "tok-env", "fp-embed", "tok-embed", "fp-env", "tok-env"},
		{"仅令牌走环境变量", "", "tok-env", "fp-embed", "tok-embed", "fp-embed", "tok-env"},
		{"仅指纹走环境变量", "fp-env", "", "fp-embed", "tok-embed", "fp-env", "tok-embed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("MXCWPP_CA_FINGERPRINT", c.envFP)
			t.Setenv("MXCWPP_ENROLL_TOKEN", c.envToken)
			fp, tok := resolveTrustConfig(c.embedFP, c.embedToken)
			if fp != c.wantFP {
				t.Errorf("fingerprint = %q, want %q", fp, c.wantFP)
			}
			if tok != c.wantToken {
				t.Errorf("token = %q, want %q", tok, c.wantToken)
			}
		})
	}
}
