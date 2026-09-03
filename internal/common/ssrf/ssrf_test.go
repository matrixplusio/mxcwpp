package ssrf

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // 回环
		"10.0.0.5", "172.16.0.1", "192.168.1.1", // 私网
		"169.254.169.254", // 云元数据（链路本地）
		"fe80::1",         // IPv6 链路本地
		"0.0.0.0", "::",   // 未指定
		"fc00::1", // IPv6 ULA(私网)
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); ip == nil || !isBlockedIP(ip) {
			t.Errorf("%s 应被判为受限网段", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); ip == nil || isBlockedIP(ip) {
			t.Errorf("%s 应被放行（公网）", s)
		}
	}
}

func TestValidateURLScheme(t *testing.T) {
	// 非 http(s) 协议一律拒绝（file/gopher/ftp 等 SSRF 常用跳板）
	for _, raw := range []string{"file:///etc/passwd", "gopher://x", "ftp://x", "//noscheme"} {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("%q 应被协议校验拒绝", raw)
		}
	}
	// 指向回环的 http 应被拒（解析后 IP 命中受限网段）
	if err := ValidateURL("http://127.0.0.1:8080/x"); err == nil {
		t.Error("http://127.0.0.1 应被拒绝")
	}
	if err := ValidateURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("云元数据地址应被拒绝")
	}
}
