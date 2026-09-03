package celengine

import "testing"

// TestIOCInboundSuppressed 锁定 IOC 入站方向抑制语义：
// 仅 ip 类 + 入站被抑制(公网被扫);出站、hash/url、方向缺失均保留告警。
func TestIOCInboundSuppressed(t *testing.T) {
	cases := []struct {
		iocType   string
		direction string
		want      bool
	}{
		{"ip", "inbound", true},    // 公网被扫描 → 抑制
		{"ip", "outbound", false},  // 本机外联恶意 IP → 真 C2,保留
		{"ip", "", false},          // 方向缺失 → 保守保留
		{"hash", "inbound", false}, // hash 无方向语义,不受限
		{"url", "inbound", false},  // url 无方向语义,不受限
	}
	for _, tc := range cases {
		if got := iocInboundSuppressed(tc.iocType, tc.direction); got != tc.want {
			t.Errorf("iocInboundSuppressed(%q,%q)=%v, want %v", tc.iocType, tc.direction, got, tc.want)
		}
	}
}
