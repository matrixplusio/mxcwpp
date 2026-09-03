package celengine

import "testing"

// TestIsInternalSource 校验内网源判定：RFC1918 / 环回 / 链路本地为内网，公网及非法输入为外网。
func TestIsInternalSource(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"10.0.0.60", true},     // 内网节点（RFC1918 10/8）
		{"172.16.0.5", true},    // RFC1918 172.16/12
		{"192.168.1.1", true},   // RFC1918 192.168/16
		{"127.0.0.1", true},     // 环回
		{"169.254.1.1", true},   // 链路本地
		{"fc00::1", true},       // IPv6 ULA
		{"8.8.8.8", false},      // 公网
		{"1.2.3.4", false},      // 公网
		{"203.0.113.10", false}, // 公网
		{"", false},             // 非法
		{"not-an-ip", false},    // 非法
	}
	for _, c := range cases {
		if got := isInternalSource(c.addr); got != c.want {
			t.Errorf("isInternalSource(%q)=%v 期望 %v", c.addr, got, c.want)
		}
	}
}

// TestClassifySeverity 校验分级：内网源恒 low（降级不消音）；外网源按端口数分级。
func TestClassifySeverity(t *testing.T) {
	d := &ScanDetector{}
	cases := []struct {
		name      string
		portCount int
		addr      string
		want      string
	}{
		{"内网源大端口数仍降 low", 80, "10.0.0.60", "low"},
		{"内网源刚过阈值降 low", 10, "192.168.0.1", "low"},
		{"外网源 <30 medium", 15, "8.8.8.8", "medium"},
		{"外网源 >=30 high", 33, "8.8.8.8", "high"},
		{"外网源 >=50 critical", 60, "1.2.3.4", "critical"},
	}
	for _, c := range cases {
		if got := d.classifySeverity(c.portCount, c.addr); got != c.want {
			t.Errorf("%s: classifySeverity(%d,%q)=%q 期望 %q", c.name, c.portCount, c.addr, got, c.want)
		}
	}
}
