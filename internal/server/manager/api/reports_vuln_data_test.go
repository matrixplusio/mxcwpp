package api

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestBuildVulnReportData_FleetScope 校验 3a：报告 severity/status 计数按舰队真实落地的去重 CVE，
// 而非 vulnerabilities advisory 全量目录（主机未命中的 CVE 不计），并修 FixedVulns 原查
// status='fixed'（枚举不存在恒 0）→ 改数主机级 host_vuln.status='patched'。
func TestBuildVulnReportData_FleetScope(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.Vulnerability{}, &model.HostVulnerability{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	now := model.ToLocalTime(time.Now())
	// 4 个 advisory CVE：仅带 host_vuln 实例的才算舰队暴露。
	vulns := []model.Vulnerability{
		{CveID: "CVE-A", Severity: "critical", Status: "unpatched", DiscoveredAt: now}, // 有 host_vuln unpatched → fleet critical
		{CveID: "CVE-B", Severity: "critical", Status: "unpatched", DiscoveredAt: now}, // advisory-only(无 host_vuln) → 不计
		{CveID: "CVE-C", Severity: "high", Status: "unpatched", DiscoveredAt: now},     // 有 host_vuln unpatched → fleet high
		{CveID: "CVE-D", Severity: "high", Status: "patched", DiscoveredAt: now},       // 有 host_vuln patched → FixedVulns
	}
	if err := db.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulns: %v", err)
	}
	hvs := []model.HostVulnerability{
		{VulnID: vulns[0].ID, HostID: "h1", Status: "unpatched"},
		{VulnID: vulns[2].ID, HostID: "h1", Status: "unpatched"},
		{VulnID: vulns[3].ID, HostID: "h1", Status: "patched"},
	}
	if err := db.Create(&hvs).Error; err != nil {
		t.Fatalf("seed host_vulns: %v", err)
	}

	h := NewReportsHandler(db, zap.NewNop())
	data := h.BuildVulnReportData(time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour))

	summary, ok := data["summary"].(gin.H)
	if !ok {
		t.Fatalf("summary 类型异常: %T", data["summary"])
	}

	assertCount := func(key string, want int64) {
		got, _ := summary[key].(int64)
		if got != want {
			t.Errorf("%s = %d, 期望 %d", key, got, want)
		}
	}
	// advisory 有 2 个 critical，但只有 1 个落到主机 → fleet critical=1（不是 2）。
	assertCount("criticalVulns", 1)
	// high：CVE-C unpatched + CVE-D patched 都在 fleet → 去重 CVE high=2。
	assertCount("highVulns", 2)
	// FixedVulns：原 status='fixed' 恒 0；改主机级 patched → 1（CVE-D）。
	assertCount("fixedVulns", 1)
	// UnpatchedVulns：fleet 未修去重 CVE = CVE-A + CVE-C = 2。
	assertCount("unpatchedVulns", 2)
}
