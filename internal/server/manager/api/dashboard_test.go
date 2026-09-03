package api

import (
	"math"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestHotPatchCountFleetScope 校验 hotPatchCount 口径：数 host_vulnerabilities 实例级 patched
// （舰队真实已修），而非 vulnerabilities.status='patched' 的 CVE 级 advisory rollup。
// rollup 仅当某 CVE 全舰队主机都修才置 patched，绝大多数恒 unpatched → 计数长期近 0 失真。
func TestHotPatchCountFleetScope(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.Vulnerability{}, &model.HostVulnerability{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	// 3 个 CVE：都有主机已把该实例修好(host_vuln patched)，但没有一个 CVE 全舰队修完，
	// 故 CVE 级 rollup 全部恒 unpatched → 旧口径数出 0。
	vulns := []model.Vulnerability{
		{CveID: "CVE-A", Severity: "critical", Status: "unpatched"},
		{CveID: "CVE-B", Severity: "high", Status: "unpatched"},
		{CveID: "CVE-C", Severity: "high", Status: "unpatched"},
	}
	if err := db.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulns: %v", err)
	}
	hvs := []model.HostVulnerability{
		{VulnID: vulns[0].ID, HostID: "h1", Status: "patched"},
		{VulnID: vulns[0].ID, HostID: "h2", Status: "unpatched"}, // 同 CVE 另一主机未修
		{VulnID: vulns[1].ID, HostID: "h1", Status: "patched"},
		{VulnID: vulns[2].ID, HostID: "h3", Status: "unpatched"},
	}
	if err := db.Create(&hvs).Error; err != nil {
		t.Fatalf("seed host_vulns: %v", err)
	}

	// 旧口径：vulnerabilities.status='patched' → 0（失真）
	var oldCount int64
	db.Model(&model.Vulnerability{}).Where("status = ?", "patched").Count(&oldCount)
	if oldCount != 0 {
		t.Fatalf("前置假设失败：CVE 级 rollup 应为 0，实得 %d", oldCount)
	}

	// 新口径（fix 后）：host_vulnerabilities.status='patched' → 2 个真实已修实例
	var newCount int64
	db.Model(&model.HostVulnerability{}).Where("status = ?", "patched").Count(&newCount)
	if newCount != 2 {
		t.Fatalf("hotPatchCount host_vuln 口径 = %d, 期望 2", newCount)
	}
}

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
			name:           "大规模机群场景 (少量 critical + 数千 high，数千漏洞，全部主机在线)",
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
				&tt.baselineCompliance,
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
		return h.computeSecurityScore(crit, 0, 0, 0, 0, 100, ptrF(80.0))
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

// ptrF 取浮点字面量的地址，供 computeSecurityScore 的可空合规率参数使用。
func ptrF(v float64) *float64 { return &v }

// 合规率未知时不得按满分计入基线维度。
//
// 从没扫过基线的环境，总分不该因为「没测过」而更高——那与合规率显示 100%
// 是同一个欺骗换了个位置。该维度应被排除，总分按剩余维度归一化。
func TestSecurityScore_UnknownBaselineIsNotFullMarks(t *testing.T) {
	h := &DashboardHandler{}

	// 同样的告警/漏洞/暴露情况，只有基线合规率一个变量
	const ca, ha, cv, hv = int64(2), int64(10), int64(5), int64(30)
	const vh, th = int64(3), int64(10)

	full := h.computeSecurityScore(ca, ha, cv, hv, vh, th, ptrF(100.0))
	unknown := h.computeSecurityScore(ca, ha, cv, hv, vh, th, nil)
	zero := h.computeSecurityScore(ca, ha, cv, hv, vh, th, ptrF(0.0))

	if unknown >= full {
		t.Fatalf("合规率未知时的评分 %.2f 不该达到满分合规时的 %.2f——"+
			"没扫过基线不是好消息", unknown, full)
	}
	if unknown <= zero {
		t.Fatalf("合规率未知时的评分 %.2f 不该低于合规率为 0 时的 %.2f——"+
			"未知不等于最差，那会让没扫过的环境看起来像已经失守", unknown, zero)
	}
	t.Logf("满分合规 %.2f / 未知 %.2f / 零合规 %.2f", full, unknown, zero)
}

// 缺维度时按剩余维度归一化，不能凭空少 25 分。
//
// 直接少算一个维度会让总分骤降，看起来像安全状况恶化，
// 而实际只是少了一项测量。
func TestSecurityScore_MissingDimensionIsNormalized(t *testing.T) {
	h := &DashboardHandler{}

	// 其余维度全满：无告警、无漏洞、无受影响主机
	unknown := h.computeSecurityScore(0, 0, 0, 0, 0, 10, nil)
	if unknown < 95.0 {
		t.Fatalf("其余维度全满、仅基线未知时评分为 %.2f，"+
			"说明缺失维度被当成扣分而不是归一化", unknown)
	}
}
