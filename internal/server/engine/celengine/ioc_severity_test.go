package celengine

import "testing"

// TestIocSeverityAndRisk 校验 M3：IOC 命中按类型置信度分级，不再一律 critical/85。
func TestIocSeverityAndRisk(t *testing.T) {
	cases := []struct {
		iocType  string
		wantSev  string
		wantRisk int
	}{
		{"hash", "critical", 90}, // 文件哈希精确匹配，高置信
		{"url", "high", 72},
		{"ip", "high", 65}, // IP 共享/CDN/复用，降级
		{"unknown", "high", 60},
	}
	for _, c := range cases {
		sev, risk := iocSeverityAndRisk(c.iocType)
		if sev != c.wantSev || risk != c.wantRisk {
			t.Errorf("iocSeverityAndRisk(%q) = (%q,%d), 期望 (%q,%d)", c.iocType, sev, risk, c.wantSev, c.wantRisk)
		}
	}
	// hash 严于 ip（回归保证分级方向）。
	_, hashRisk := iocSeverityAndRisk("hash")
	_, ipRisk := iocSeverityAndRisk("ip")
	if hashRisk <= ipRisk {
		t.Errorf("hash 风险(%d) 应高于 ip(%d)", hashRisk, ipRisk)
	}
}
