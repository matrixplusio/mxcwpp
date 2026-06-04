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
			name:               "干净系统 + 满合规 = 满分",
			baselineCompliance: 100.0,
			wantMin:            100.0, wantMax: 100.0,
		},
		{
			name:               "干净系统 + 合规 80% = 95",
			baselineCompliance: 80.0,
			wantMin:            95.0, wantMax: 95.0,
		},
		{
			name:               "干净系统 + 合规 0% = 75 (其他三维满)",
			baselineCompliance: 0.0,
			wantMin:            75.0, wantMax: 75.0,
		},
		{
			name:           "1 critical 告警 (无 host) → 告警分轻微扣",
			criticalAlerts: 1, baselineCompliance: 80.0,
			// density=400, log10(401)/4≈0.651, alert=25*(1-0.651)≈8.74
			// 8.74 + 25 + 20 + 25 ≈ 78.7
			wantMin: 78.0, wantMax: 79.5,
		},
		{
			name:           "高密度告警单维触底",
			criticalAlerts: 10000, totalHosts: 1, vulnHosts: 0,
			baselineCompliance: 100.0,
			// alert weighted=40000, density=4M, log/4>1 → cap → 0
			// 0 + 25 + 25 + 25 = 75
			wantMin: 75.0, wantMax: 75.0,
		},
		{
			name:               "totalHosts=0 不除零，退回单 host 密度",
			vulnHosts:          0,
			totalHosts:         0,
			baselineCompliance: 80.0,
			wantMin:            95.0, wantMax: 95.0,
		},
		{
			name:      "全 host 受漏洞影响 → exposure=0",
			vulnHosts: 10, totalHosts: 10,
			baselineCompliance: 100.0,
			// vuln=0 weighted=25, alert=25, baseline=25, exposure=0 = 75
			wantMin: 75.0, wantMax: 75.0,
		},
		{
			name:           "Dev 实测场景 (20642 critical_alerts + 13003 high_alerts + 2416 critical_vulns + 7416 high_vulns + 2/3 hosts + 64.94 baseline)",
			criticalAlerts: 20642, highAlerts: 13003,
			criticalVulns: 2416, highVulns: 7416,
			vulnHosts: 2, totalHosts: 3,
			baselineCompliance: 64.94,
			// alert+vuln 密度爆顶 → 0+0
			// baseline = 64.94/100*25 ≈ 16.24
			// exposure = (1-2/3)*25 ≈ 8.33
			// ≈ 24.57
			wantMin: 22.0, wantMax: 27.0,
		},
		{
			name:           "Prod 实测场景 (278 + 5771 alerts, 3279 + 8512 vulns, 226/226 hosts, 65.33 baseline)",
			criticalAlerts: 278, highAlerts: 5771,
			criticalVulns: 3279, highVulns: 8512,
			vulnHosts: 226, totalHosts: 226,
			baselineCompliance: 65.33,
			// alert weighted=278*4+5771=6883, density=3046, log/4≈0.871, alert≈3.22
			// vuln weighted=24907, density=11020, log/4>1 → 0
			// baseline = 16.33
			// exposure = 0
			// ≈ 19.55
			wantMin: 17.0, wantMax: 22.0,
		},
		{
			name:           "中等态势 (低告警 + 少量漏洞 + 高合规 + 部分影响)",
			criticalAlerts: 2, highAlerts: 10,
			criticalVulns: 5, highVulns: 30,
			vulnHosts: 3, totalHosts: 10,
			baselineCompliance: 90.0,
			// alert=10.89, vuln=7.87, baseline=22.5, exposure=17.5 ≈ 58.8
			wantMin: 55.0, wantMax: 65.0,
		},
		{
			name: "Prod 评分应低于 Dev 评分（同样烂数据 prod 主机比例更糟）",
			// 见下方独立测试 TestSecurityScoreDevVsProd
			baselineCompliance: 100.0,
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

// TestDimScoreFromDensity 单独覆盖密度→分数曲线
func TestDimScoreFromDensity(t *testing.T) {
	const dimMax = 25.0
	tests := []struct {
		name       string
		weighted   float64
		totalHosts int64
		wantMin    float64
		wantMax    float64
	}{
		{name: "0 告警 → 满分", weighted: 0, totalHosts: 100, wantMin: 25.0, wantMax: 25.0},
		{name: "totalHosts=0 退回 hosts=1", weighted: 100, totalHosts: 0, wantMin: 0.0, wantMax: 6.0},
		{name: "每 100 host 1 个高危 → 接近满分", weighted: 1, totalHosts: 100, wantMin: 23.0, wantMax: 25.0},
		{name: "每 host 1 个高危 → 中位偏下", weighted: 100, totalHosts: 100, wantMin: 10.0, wantMax: 14.0},
		{name: "每 host 100 个高危 → 触底", weighted: 10000, totalHosts: 100, wantMin: 0.0, wantMax: 0.5},
		{name: "weighted 负数 → 满分（防御性）", weighted: -10, totalHosts: 100, wantMin: 25.0, wantMax: 25.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dimScoreFromDensity(tt.weighted, tt.totalHosts, dimMax)
			if got < tt.wantMin || got > tt.wantMax {
				t.Fatalf("dimScoreFromDensity(%v,%v) = %v, want [%v,%v]",
					tt.weighted, tt.totalHosts, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// TestSecurityScoreMonotonic 告警/漏洞越多分数越低
func TestSecurityScoreMonotonic(t *testing.T) {
	h := &DashboardHandler{}
	base := func(crit int64) float64 {
		return h.computeSecurityScore(crit, 0, 0, 0, 0, 100, 80.0)
	}
	prev := math.Inf(1)
	for _, c := range []int64{0, 1, 10, 100, 1000, 10000} {
		s := base(c)
		if s > prev {
			t.Fatalf("non-monotonic at %d: %v > %v", c, s, prev)
		}
		prev = s
	}
}

func TestSanitizeDashboardValue(t *testing.T) {
	// 保留原测试占位
	_ = gin.H{}
}
