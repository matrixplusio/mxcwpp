package collector

import "testing"

// TestDirectionForLocalPort 校验 H1：procfs 降级路径按 LISTEN 端口集推断连接方向。
func TestDirectionForLocalPort(t *testing.T) {
	listen := map[int]struct{}{22: {}, 443: {}, 8080: {}}
	cases := []struct {
		localPort int
		want      string
	}{
		{22, "inbound"},     // 别人连我们的 SSH → 入站
		{443, "inbound"},    // 别人连我们的 HTTPS 服务 → 入站
		{54321, "outbound"}, // 本机临时端口主动外联 → 出站
		{8080, "inbound"},
		{40000, "outbound"},
	}
	for _, c := range cases {
		if got := directionForLocalPort(listen, c.localPort); got != c.want {
			t.Errorf("directionForLocalPort(localPort=%d) = %q, 期望 %q", c.localPort, got, c.want)
		}
	}
	// 空监听集 → 一律 outbound。
	if got := directionForLocalPort(nil, 22); got != "outbound" {
		t.Errorf("空监听集应 outbound, 得 %q", got)
	}
}
