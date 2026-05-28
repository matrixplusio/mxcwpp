package api

import (
	"math"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestComputeSecurityScore(t *testing.T) {
	h := &DashboardHandler{}

	tests := []struct {
		name               string
		criticalAlerts     int64
		highAlerts         int64
		criticalVulns      int64
		highVulns          int64
		vulnHosts          int64
		totalHosts         int64
		baselineCompliance float64
		wantMin            float64
		wantMax            float64
	}{
		{
			name:               "干净系统满分",
			baselineCompliance: 100.0,
			wantMin:            100.0, wantMax: 100.0,
		},
		{
			name:               "合规率 80% 基准无扣分",
			baselineCompliance: 80.0,
			wantMin:            100.0, wantMax: 100.0,
		},
		{
			name:           "1 个 critical 告警扣 2 分",
			criticalAlerts: 1, baselineCompliance: 80.0,
			wantMin: 98.0, wantMax: 98.0,
		},
		{
			name:           "100 个 critical 告警封顶扣 30",
			criticalAlerts: 100, baselineCompliance: 80.0,
			wantMin: 70.0, wantMax: 70.0,
		},
		{
			name:          "用户场景 277 严重 + 5488 高危漏洞 + 209/总主机受影响",
			criticalVulns: 277, highVulns: 5488,
			vulnHosts: 209, totalHosts: 209,
			baselineCompliance: 50.0,
			// critical_vuln: min(277*0.05, 20) = 13.85
			// high_vuln:     min(5488*0.01, 10) = 10
			// affected:      209/209 * 20 = 20
			// compliance:    (50-80) * 0.1 = -3
			// 100 - 13.85 - 10 - 20 - 3 = 53.15
			wantMin: 53.0, wantMax: 53.3,
		},
		{
			name:           "极端：critical=50, high=50, vuln 全爆 + 全主机受影响 + 0 合规",
			criticalAlerts: 50, highAlerts: 50,
			criticalVulns: 10000, highVulns: 10000,
			vulnHosts: 1000, totalHosts: 1000,
			baselineCompliance: 0.0,
			// 100 - 30 - 20 - 20 - 10 - 20 - 8 = -8 → 0
			wantMin: 0.0, wantMax: 0.0,
		},
		{
			name:               "合规率 100% 额外加 2 分但封顶 100",
			baselineCompliance: 100.0,
			wantMin:            100.0, wantMax: 100.0,
		},
		{
			name:               "totalHosts=0 应不触发除零",
			vulnHosts:          0,
			totalHosts:         0,
			baselineCompliance: 80.0,
			wantMin:            100.0, wantMax: 100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.computeSecurityScore(
				tt.criticalAlerts, tt.highAlerts,
				tt.criticalVulns, tt.highVulns,
				tt.vulnHosts, tt.totalHosts,
				tt.baselineCompliance,
			)
			if got < tt.wantMin || got > tt.wantMax {
				t.Fatalf("computeSecurityScore() = %v, want range [%v, %v]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestSanitizeDashboardValue(t *testing.T) {
	input := gin.H{
		"avgCpuUsage":    math.NaN(),
		"avgMemoryUsage": math.Inf(1),
		"baseline": gin.H{
			"percent": math.Inf(-1),
		},
		"baselineRisks": []gin.H{
			{"score": math.NaN()},
			{"score": 42.5},
		},
	}

	sanitized := sanitizeDashboardValue(input).(gin.H)

	if got := sanitized["avgCpuUsage"].(float64); got != 0 {
		t.Fatalf("avgCpuUsage = %v, want 0", got)
	}
	if got := sanitized["avgMemoryUsage"].(float64); got != 0 {
		t.Fatalf("avgMemoryUsage = %v, want 0", got)
	}

	baseline := sanitized["baseline"].(gin.H)
	if got := baseline["percent"].(float64); got != 0 {
		t.Fatalf("baseline.percent = %v, want 0", got)
	}

	baselineRisks := sanitized["baselineRisks"].([]gin.H)
	if got := baselineRisks[0]["score"].(float64); got != 0 {
		t.Fatalf("baselineRisks[0].score = %v, want 0", got)
	}
	if got := baselineRisks[1]["score"].(float64); got != 42.5 {
		t.Fatalf("baselineRisks[1].score = %v, want 42.5", got)
	}
}
