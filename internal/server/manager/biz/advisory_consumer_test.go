package biz

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// setupAdvisoryIngestDB 复用 reconcile 测试的全列建表（vulnerabilities/host_vulnerabilities/
// software/hosts），再补 advisory ingest 写路径需要的 advisory_packages 表。
func setupAdvisoryIngestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupReconcileTestDB(t)
	require.NoError(t, db.Exec(`CREATE TABLE advisory_packages (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id                 INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id             TEXT NOT NULL,
		source             TEXT NOT NULL,
		source_advisory_id TEXT,
		os_family          TEXT NOT NULL DEFAULT '',
		os_major           TEXT NOT NULL DEFAULT '',
		ecosystem          TEXT DEFAULT '',
		pkg_name           TEXT NOT NULL,
		arch               TEXT DEFAULT '',
		fixed_version      TEXT NOT NULL,
		confidence         TEXT DEFAULT 'high',
		severity           TEXT DEFAULT '',
		issued_at          DATETIME,
		created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(cve_id, source, os_family, os_major, pkg_name, arch)
	)`).Error)
	return db
}

// TestIngestAdvisories_MatchesVulnerableHostOnly 验证消费路径（Coordinator.IngestAdvisories）
// 精确 NEVRA 比对：仅给「装了低于 fixed 版本」的主机写 host_vuln，已打补丁主机不写。
// 这是取代 syncCoreAdvisories 自拉路径的等价性单元证据。
func TestIngestAdvisories_MatchesVulnerableHostOnly(t *testing.T) {
	db := setupAdvisoryIngestDB(t)
	coord := advisory.NewCoordinator(db, zap.NewNop())

	msgs := []advisory.AdvisoryMessage{
		{
			Source:     "rhsa",
			Confidence: advisory.ConfidenceHigh,
			Advisory: &advisory.Advisory{
				AdvisoryID:   "RHSA-2024:1234",
				CVEIDs:       []string{"CVE-2024-0001"},
				Severity:     advisory.SeverityHigh,
				OSFamily:     "rhel",
				OSMajorVer:   "9",
				AffectedPkgs: []advisory.PkgFix{{Name: "openssl", FixedVersion: "1:3.5.5-1.el9_4"}},
			},
		},
	}
	hosts := []advisory.HostSoftware{
		{ // 漏洞主机：openssl 3.5.1 < fixed 3.5.5 → 应写 host_vuln
			HostID: "host-vuln", OSFamily: "rhel", OSMajor: "9",
			PkgName: "openssl", PkgEpoch: "1", PkgVerRaw: "3.5.1", PkgRelease: "3.el9", PkgManager: "rpm",
		},
		{ // 已打补丁主机：openssl 3.5.5-1.el9_4 == fixed → 不应写 host_vuln
			HostID: "host-patched", OSFamily: "rhel", OSMajor: "9",
			PkgName: "openssl", PkgEpoch: "1", PkgVerRaw: "3.5.5", PkgRelease: "1.el9_4", PkgManager: "rpm",
		},
	}

	vulnCount, hostVulnCount := coord.IngestAdvisories(msgs, hosts)
	require.Equal(t, 1, vulnCount, "应入库 1 条 vulnerability")
	require.Equal(t, 1, hostVulnCount, "仅漏洞主机关联，已打补丁主机不关联")

	var hvs []model.HostVulnerability
	require.NoError(t, db.Find(&hvs).Error)
	require.Len(t, hvs, 1)
	require.Equal(t, "host-vuln", hvs[0].HostID)

	// 幂等：重复消费同一批不产生重复 host_vuln
	coord.IngestAdvisories(msgs, hosts)
	var cnt int64
	require.NoError(t, db.Model(&model.HostVulnerability{}).Count(&cnt).Error)
	require.Equal(t, int64(1), cnt, "重放幂等，host_vuln 不重复")
}
