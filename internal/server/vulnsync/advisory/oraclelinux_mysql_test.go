package advisory_test

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/migration"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// 针对真实 MySQL 的 Oracle Linux 端到端验证。不设 PROBE_DSN 时自动跳过；库必须是空的一次性库。
//
//	PROBE_DSN='root:pass@tcp(127.0.0.1:3306)/scratch?charset=utf8mb4&parseTime=True&loc=Local' \
//	    go test ./internal/server/vulnsync/advisory/ -run MySQL
//
// Oracle Linux 主机上报 os_family="ol"。匹配器与清理 SQL 原先只认 "oraclelinux"，
// 于是 RHSA 匹配不到这些主机；就算匹配到，跨系列清理也会把关联当成跨发行版误报删掉。
// 包版本用的是 Oracle 插入 ".0.N" 段的写法且落后两个小版本：已修复判定若不还原成 RHEL 写法，
// 会把它判成已修复删掉。清理是 SQL，只有真库能验证。
func TestOracleLinuxRHSALinkSurvivesCleanupMySQL(t *testing.T) {
	dsn := os.Getenv("PROBE_DSN")
	if dsn == "" {
		t.Skip("未设置 PROBE_DSN，跳过 MySQL 集成验证")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}
	logger := zap.NewNop()
	if err := migration.Migrate(db, logger); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	const cve = "CVE-2099-0001"
	for _, h := range []struct{ id, family string }{{"ol-host", "ol"}, {"ubuntu-host", "ubuntu"}} {
		if err := db.Create(&model.Host{HostID: h.id, Hostname: h.id, OSFamily: h.family, OSVersion: "8.10", Status: "online"}).Error; err != nil {
			t.Fatalf("建主机: %v", err)
		}
		if err := db.Create(&model.Software{ID: h.id + "-glibc", HostID: h.id, Name: "glibc", Version: "2.28",
			Release: "251.0.3.el8_10.25", Architecture: "x86_64", PackageType: "rpm", CollectedAt: model.LocalTime(time.Now())}).Error; err != nil {
			t.Fatalf("建软件: %v", err)
		}
	}

	msgs := []advisory.AdvisoryMessage{{
		Source:     "rhsa",
		Confidence: advisory.ConfidenceHigh,
		Advisory: &advisory.Advisory{
			AdvisoryID: "RHSA-2099:0001", CVEIDs: []string{cve}, Severity: advisory.SeverityHigh,
			Description: "test", IssuedAt: time.Now(), OSFamily: "rhel", OSMajorVer: "8",
			AffectedPkgs: []advisory.PkgFix{{Name: "glibc", Arch: "x86_64", FixedVersion: "2.28-251.el8_10.27"}},
		},
	}}
	hosts := []advisory.HostSoftware{{
		HostID: "ol-host", Hostname: "ol-host", OSFamily: "ol", OSVer: "8.10", OSMajor: "8", Arch: "amd64",
		PkgName: "glibc", PkgArch: "x86_64", PkgVerRaw: "2.28", PkgRelease: "251.0.3.el8_10.25",
		PkgVer: "2.28-251.0.3.el8_10.25", PkgManager: "rpm",
	}}
	if _, err := advisory.NewCoordinator(db, logger).IngestAdvisories(msgs, hosts); err != nil {
		t.Fatalf("入库失败: %v", err)
	}

	var vuln model.Vulnerability
	if err := db.Where("cve_id = ?", cve).First(&vuln).Error; err != nil {
		t.Fatalf("漏洞未入库: %v", err)
	}
	linked := func(hostID string) bool {
		var n int64
		db.Model(&model.HostVulnerability{}).Where("host_id = ? AND vuln_id = ?", hostID, vuln.ID).Count(&n)
		return n > 0
	}
	if !linked("ol-host") {
		t.Fatal("RHSA 没有匹配到 os_family=ol 的主机")
	}
	// 对照组：同一条 RHSA 挂在 Ubuntu 主机上是跨发行版误报，清理必须删掉它，证明清理确实跑了。
	if err := db.Create(&model.HostVulnerability{HostID: "ubuntu-host", VulnID: vuln.ID, Status: "unpatched"}).Error; err != nil {
		t.Fatalf("建对照关联: %v", err)
	}

	advisory.CleanupHostVulnFP(db, logger)
	advisory.CleanupAlreadyPatched(db, logger)

	if !linked("ol-host") {
		t.Error("清理删掉了 Oracle Linux 主机的 RHSA 关联：跨系列判定或已修复判定没有认出 Oracle 的写法")
	}
	if linked("ubuntu-host") {
		t.Error("对照组未被清理：清理没有生效，本测试不能证明任何事")
	}
}
