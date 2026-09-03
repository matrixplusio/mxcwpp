package biz

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupReconcileTestDB 建 sqlite 内存库 + 手动建表
// 手动 CREATE TABLE 而非 AutoMigrate：避免 GORM 在 sqlite 上的 MySQL 专有索引语法报错
func setupReconcileTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	tables := []string{
		`CREATE TABLE hosts (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			host_id       TEXT PRIMARY KEY,
			hostname      TEXT,
			ipv4          TEXT DEFAULT '[]',
			status        TEXT DEFAULT 'offline',
			business_line TEXT
		)`,
		`CREATE TABLE vulnerabilities (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id            TEXT NOT NULL UNIQUE,
			osv_id            TEXT,
			purl              TEXT,
			severity          TEXT NOT NULL DEFAULT 'medium',
			cvss_score        REAL DEFAULT 0,
			component         TEXT,
			description       TEXT,
			affected_hosts    INTEGER DEFAULT 0,
			patched_hosts     INTEGER DEFAULT 0,
			status            TEXT NOT NULL DEFAULT 'unpatched',
			discovered_at     DATETIME,
			patched_at        DATETIME,
			current_version   TEXT,
			fixed_version     TEXT,
			reference_url     TEXT,
			cvss_vector       TEXT,
			attack_vector     TEXT,
			vuln_type         TEXT,
			affected_versions TEXT,
			source            TEXT,
			patch_available   INTEGER DEFAULT 0,
			epss_score        REAL DEFAULT 0,
			cwe_id            TEXT,
			cwe_category      TEXT DEFAULT 'other',
			cnvd_id           TEXT,
			cnnvd_id          TEXT,
			has_exploit       INTEGER DEFAULT 0,
			in_kev            INTEGER DEFAULT 0,
			exploit_ref       TEXT,
			priority_score    REAL DEFAULT 0,
			exposure_score    REAL DEFAULT 0,
			confidence        TEXT DEFAULT 'low',
			vuln_category     TEXT DEFAULT 'other',
			restart_action    TEXT DEFAULT 'unknown',
			vuln_category_override   TEXT,
			restart_action_override  TEXT,
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			deleted_at        DATETIME
		)`,
		`CREATE TABLE host_vulnerabilities (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id         INTEGER NOT NULL,
			host_id         TEXT NOT NULL,
			hostname        TEXT,
			ip              TEXT,
			current_version TEXT,
			status          TEXT NOT NULL DEFAULT 'unpatched',
			patched_at      DATETIME,
			asset_type      TEXT DEFAULT 'unknown',
			subscope        TEXT DEFAULT 'unknown',
			fix_owner       TEXT DEFAULT 'unknown',
			host_binary_path TEXT,
			precheck_status  TEXT DEFAULT 'unchecked',
			precheck_message TEXT,
			precheck_packages TEXT,
			precheck_affected_processes TEXT,
			precheck_checked_at DATETIME,
			patched_reason   TEXT DEFAULT '',
			prev_status      TEXT DEFAULT '',
			vanished_at      DATETIME,
			resurfaced_at    DATETIME,
			matched_component     TEXT DEFAULT '',
			matched_fixed_version TEXT DEFAULT '',
			created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(vuln_id, host_id)
		)`,
		`CREATE TABLE software (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id              TEXT PRIMARY KEY,
			host_id         TEXT NOT NULL,
			name            TEXT NOT NULL,
			version         TEXT,
			architecture    TEXT,
			package_type    TEXT NOT NULL DEFAULT 'rpm',
			vendor          TEXT,
			install_time    TEXT,
			purl            TEXT,
			ecosystem       TEXT,
			source_file     TEXT,
			scope           TEXT DEFAULT 'system',
			source_handler  TEXT,
			host_binary_path TEXT,
			epoch           TEXT,
			release         TEXT,
			collected_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		require.NoError(t, db.Exec(ddl).Error, "failed DDL: %s", ddl)
	}
	return db
}

// TestReconcileHostVulns_PrefersMatchedFixedVersion 校验 3c：核销用 per-host
// matched_fixed_version（该主机 OS 分支的适用修复版）+ 权威比较器，而非 CVE 级塌缩
// fixed_version。CVE 级值偏低时旧逻辑会误标已修，本例应保持 unpatched。
func TestReconcileHostVulns_PrefersMatchedFixedVersion(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-0001",
		Severity:     "high",
		PURL:         "pkg:rpm/openssl",
		FixedVersion: "1.0", // CVE 级塌缩值（偏低）
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:              vuln.ID,
		HostID:              "host-1",
		CurrentVersion:      "1.5",
		Status:              model.HostVulnStatusUnpatched,
		MatchedFixedVersion: "2.0", // per-host 适用修复版（更高）
	}
	require.NoError(t, db.Create(&hv).Error)

	// 主机当前装 1.5：>= CVE 级 1.0，但 < per-host 2.0。
	require.NoError(t, db.Exec(
		`INSERT INTO software (id, host_id, name, version, purl) VALUES (?,?,?,?,?)`,
		"sw1", "host-1", "openssl", "1.5", "pkg:rpm/openssl").Error)

	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	// 用 per-host 2.0：1.5 < 2.0 → 不核销（旧逻辑用 CVE 1.0 会误标 patched）。
	assert.Equal(t, 0, result.Patched)
	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusUnpatched, got.Status)
}

func TestReconcileHostVulns_PackageRemoved_MarksVanished(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-39830",
		Severity:     "critical",
		PURL:         "pkg:golang/golang.org/x/crypto",
		FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:         vuln.ID,
		HostID:         "host-1",
		CurrentVersion: "v0.38.0",
		Status:         model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	// software 表故意不放该包，模拟包消失
	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 1, result.Vanished)
	assert.Equal(t, 0, result.Patched)

	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusVanished, got.Status)
	assert.Equal(t, model.PatchedReasonPackageRemoved, got.PatchedReason)
	assert.Equal(t, model.HostVulnStatusUnpatched, got.PrevStatus)
	require.NotNil(t, got.VanishedAt)
}

func TestReconcileHostVulns_VersionMeetsFix_MarksPatched(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-39830",
		Severity:     "critical",
		PURL:         "pkg:golang/golang.org/x/crypto",
		FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:         vuln.ID,
		HostID:         "host-1",
		CurrentVersion: "v0.38.0",
		Status:         model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	sw := model.Software{
		ID:      "sw-1",
		HostID:  "host-1",
		Name:    "golang.org/x/crypto",
		Version: "v0.52.0",
		PURL:    "pkg:golang/golang.org/x/crypto",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished)
	assert.Equal(t, 1, result.Patched)

	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusPatched, got.Status)
	assert.Equal(t, model.PatchedReasonAutoVersionMatch, got.PatchedReason)
	require.NotNil(t, got.PatchedAt)
	assert.Equal(t, "v0.52.0", got.CurrentVersion)
}

func TestReconcileHostVulns_VersionStillLow_KeepsUnpatched(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-39830",
		Severity:     "critical",
		PURL:         "pkg:golang/golang.org/x/crypto",
		FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:         vuln.ID,
		HostID:         "host-1",
		CurrentVersion: "v0.38.0",
		Status:         model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	sw := model.Software{
		ID:      "sw-1",
		HostID:  "host-1",
		Name:    "golang.org/x/crypto",
		Version: "v0.47.0",
		PURL:    "pkg:golang/golang.org/x/crypto",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished)
	assert.Equal(t, 0, result.Patched)

	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusUnpatched, got.Status)
	assert.Equal(t, "v0.47.0", got.CurrentVersion, "应更新 current_version 跟踪")
}

func TestReconcileHostVulns_FixedVersionEmpty_NoChange(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-39830",
		Severity:     "critical",
		PURL:         "pkg:golang/golang.org/x/crypto",
		FixedVersion: "",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:         vuln.ID,
		HostID:         "host-1",
		CurrentVersion: "v0.38.0",
		Status:         model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	sw := model.Software{
		ID:      "sw-1",
		HostID:  "host-1",
		Name:    "golang.org/x/crypto",
		Version: "v0.52.0",
		PURL:    "pkg:golang/golang.org/x/crypto",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished)
	assert.Equal(t, 0, result.Patched, "fixed_version 空时不应标 patched")
}

func TestReconcileHostVulns_MultipleHosts_BatchCorrect(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-39830",
		Severity:     "critical",
		PURL:         "pkg:golang/golang.org/x/crypto",
		FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	for _, hostID := range []string{"host-1", "host-2", "host-3"} {
		require.NoError(t, db.Create(&model.HostVulnerability{
			VulnID: vuln.ID, HostID: hostID,
			CurrentVersion: "v0.38.0",
			Status:         model.HostVulnStatusUnpatched,
		}).Error)
	}
	require.NoError(t, db.Create(&model.Software{
		ID: "sw-2", HostID: "host-2",
		Name: "golang.org/x/crypto", Version: "v0.52.0",
		PURL: "pkg:golang/golang.org/x/crypto",
	}).Error)
	require.NoError(t, db.Create(&model.Software{
		ID: "sw-3", HostID: "host-3",
		Name: "golang.org/x/crypto", Version: "v0.47.0",
		PURL: "pkg:golang/golang.org/x/crypto",
	}).Error)

	rec := NewVulnReconciler(db, logger)
	result, err := rec.ReconcileHosts([]string{"host-1", "host-2", "host-3"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Vanished)
	assert.Equal(t, 1, result.Patched)
}

func TestReconcileHostVulns_PrevPatchedReappears_MarksResurfaced(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID: "CVE-2026-39830", Severity: "critical",
		PURL: "pkg:golang/golang.org/x/crypto", FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	patchedTime := model.LocalTime(time.Now().Add(-24 * time.Hour))
	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "v0.52.0",
		Status:         model.HostVulnStatusPatched,
		PrevStatus:     model.HostVulnStatusUnpatched,
		PatchedReason:  model.PatchedReasonAutoVersionMatch,
		PatchedAt:      &patchedTime,
	}
	require.NoError(t, db.Create(&hv).Error)

	// software 表显示版本回滚到漏洞版本（依赖回滚等场景）
	require.NoError(t, db.Create(&model.Software{
		ID: "sw-1", HostID: "host-1",
		Name: "golang.org/x/crypto", Version: "v0.38.0",
		PURL: "pkg:golang/golang.org/x/crypto",
	}).Error)

	rec := NewVulnReconciler(db, logger)
	count := rec.DetectResurfaced([]string{"host-1"})

	assert.Equal(t, 1, count)
	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusResurfaced, got.Status)
	assert.Equal(t, model.HostVulnStatusPatched, got.PrevStatus)
	require.NotNil(t, got.ResurfacedAt)
}

func TestReconcileHostVulns_PrevVanishedReappears_MarksResurfaced(t *testing.T) {
	db := setupReconcileTestDB(t)
	logger := zap.NewNop()

	vuln := model.Vulnerability{
		CveID: "CVE-2026-39830", Severity: "critical",
		PURL: "pkg:golang/golang.org/x/crypto", FixedVersion: "0.52.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	vanishedTime := model.LocalTime(time.Now().Add(-24 * time.Hour))
	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "v0.38.0",
		Status:         model.HostVulnStatusVanished,
		PrevStatus:     model.HostVulnStatusUnpatched,
		PatchedReason:  model.PatchedReasonPackageRemoved,
		VanishedAt:     &vanishedTime,
	}
	require.NoError(t, db.Create(&hv).Error)

	require.NoError(t, db.Create(&model.Software{
		ID: "sw-1", HostID: "host-1",
		Name: "golang.org/x/crypto", Version: "v0.38.0",
		PURL: "pkg:golang/golang.org/x/crypto",
	}).Error)

	rec := NewVulnReconciler(db, logger)
	count := rec.DetectResurfaced([]string{"host-1"})

	assert.Equal(t, 1, count)
	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusResurfaced, got.Status)
	assert.Equal(t, model.HostVulnStatusVanished, got.PrevStatus)
}

// 漏洞 PURL 带「易受攻击版本」，主机 software PURL 带「已安装版本」，
// 两者几乎永不相等。按完整 PURL 匹配会把仍然装着的包判成已卸载。
//
// 全机群首次 host-scoped reconcile：误标 vanished 的量级远超真正 patched，
// 而真正 patched 只有 206 条，横跨 os/app/middleware/unknown 全部资产类型。
//
// 既有用例全用不带版本的 PURL，因而从未暴露这条。
func TestReconcileHostVulns_VersionBearingPURL_NotFalseVanished(t *testing.T) {
	db := setupReconcileTestDB(t)

	vuln := model.Vulnerability{
		CveID:    "CVE-2026-40001",
		Severity: "high",
		// 漏洞记录里嵌的是易受攻击版本
		PURL:         "pkg:golang/github.com%2Fmoby%2Fbuildkit@v0.23.2",
		FixedVersion: "v0.24.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID:         vuln.ID,
		HostID:         "host-1",
		CurrentVersion: "v0.23.2",
		Status:         model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	// 主机上包还装着，装的是 v0.23.5——仍低于修复版 v0.24.0，所以依然受影响。
	// 但它的 PURL 嵌的是已安装版本，与漏洞记录里的 @v0.23.2 不相等。
	sw := model.Software{
		ID:      "sw-1",
		HostID:  "host-1",
		Name:    "github.com/moby/buildkit",
		Version: "v0.23.5",
		PURL:    "pkg:golang/github.com%2Fmoby%2Fbuildkit@v0.23.5",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished, "包仍然装着，不该被判为已卸载")

	var got model.HostVulnerability
	require.NoError(t, db.First(&got, hv.ID).Error)
	assert.Equal(t, model.HostVulnStatusUnpatched, got.Status,
		"版本未达修复版，应保持 unpatched")
}

// 版本已升到修复版之上时应判 patched。
//
// 误判 vanished 的另一面：本该记为 patched 的也被算成「包没了」，
// patched 数因此被严重低估（生产上 206 vs 16321）。
func TestReconcileHostVulns_VersionBearingPURL_UpgradedMarksPatched(t *testing.T) {
	db := setupReconcileTestDB(t)

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-40002",
		Severity:     "high",
		PURL:         "pkg:golang/github.com%2Fmoby%2Fbuildkit@v0.23.2",
		FixedVersion: "v0.24.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "v0.23.2", Status: model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	// 已升级：PURL 里的版本变了
	sw := model.Software{
		ID: "sw-1", HostID: "host-1",
		Name: "github.com/moby/buildkit", Version: "v0.25.0",
		PURL: "pkg:golang/github.com%2Fmoby%2Fbuildkit@v0.25.0",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished)
	assert.Equal(t, 1, result.Patched)
}

// OS 包（rpm）同样受影响——生产数据里 os 类型有 2156 条误标、0 条 patched。
func TestReconcileHostVulns_OSPackageWithVersionQualifiers(t *testing.T) {
	db := setupReconcileTestDB(t)

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-40003",
		Severity:     "high",
		PURL:         "pkg:rpm/rocky/openssl@3.0.7-24.el9?arch=x86_64",
		FixedVersion: "3.0.7-27.el9",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "3.0.7-24.el9", Status: model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	sw := model.Software{
		ID: "sw-1", HostID: "host-1",
		Name: "openssl", Version: "3.0.7-24.el9",
		PURL: "pkg:rpm/rocky/openssl@3.0.7-24.el9?arch=x86_64",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 0, result.Vanished, "OS 包仍装着，不该判为已卸载")
}

// 包确实被卸载时仍要判 vanished——修复不能把这个能力一起弄没了。
func TestReconcileHostVulns_TrulyRemoved_StillVanishes(t *testing.T) {
	db := setupReconcileTestDB(t)

	vuln := model.Vulnerability{
		CveID:        "CVE-2026-40004",
		Severity:     "high",
		PURL:         "pkg:golang/github.com%2Fgone%2Fpkg@v1.0.0",
		FixedVersion: "v2.0.0",
	}
	require.NoError(t, db.Create(&vuln).Error)

	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "v1.0.0", Status: model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	// 主机上装的是别的包
	sw := model.Software{
		ID: "sw-1", HostID: "host-1",
		Name: "other", Version: "v1.0.0",
		PURL: "pkg:golang/github.com%2Fother%2Fpkg@v1.0.0",
	}
	require.NoError(t, db.Create(&sw).Error)

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)

	assert.Equal(t, 1, result.Vanished, "包确实不在了，应判 vanished")
}

// purlIdentity 的边界：版本、限定符、子路径都要去掉，包名本身的 '@' 要留住。
func TestPurlIdentity(t *testing.T) {
	cases := []struct{ in, want, why string }{
		{"pkg:golang/github.com%2Fmoby%2Fbuildkit@v0.23.2",
			"pkg:golang/github.com%2Fmoby%2Fbuildkit", "去版本"},
		{"pkg:rpm/rocky/openssl@3.0.7-24.el9?arch=x86_64",
			"pkg:rpm/rocky/openssl", "去版本与限定符"},
		{"pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=bookworm",
			"pkg:deb/debian/curl", "多限定符"},
		{"pkg:npm/%40scope%2Fpkg@1.2.3",
			"pkg:npm/%40scope%2Fpkg", "包名含编码后的 @scope，只能切最后一个 @"},
		{"pkg:golang/example.com/mod@v1.0.0#subdir",
			"pkg:golang/example.com/mod", "去子路径"},
		{"pkg:golang/example.com/mod", "pkg:golang/example.com/mod", "本就无版本"},
		{"", "", "空串"},
	}
	for _, c := range cases {
		if got := purlIdentity(c.in); got != c.want {
			t.Errorf("%s: purlIdentity(%q) = %q，期望 %q", c.why, c.in, got, c.want)
		}
	}
}

// 同一包存在多个版本时，索引保留最高版本。
//
// 口径是「主机是否已经装上了修复版」——若保留低版本，
// 已经装了修复版的主机会被判成仍受影响。
func TestReconcileHostVulns_MultiVersionKeepsHighest(t *testing.T) {
	db := setupReconcileTestDB(t)

	vuln := model.Vulnerability{
		CveID: "CVE-2026-40005", Severity: "high",
		PURL: "pkg:golang/example.com%2Fmod@v1.0.0", FixedVersion: "v2.0.0",
	}
	require.NoError(t, db.Create(&vuln).Error)
	hv := model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-1",
		CurrentVersion: "v1.0.0", Status: model.HostVulnStatusUnpatched,
	}
	require.NoError(t, db.Create(&hv).Error)

	// 同一包两个版本并存（常见于语言包多版本共存）
	require.NoError(t, db.Create(&model.Software{
		ID: "sw-1", HostID: "host-1", Name: "example.com/mod",
		Version: "v1.0.0", PURL: "pkg:golang/example.com%2Fmod@v1.0.0",
	}).Error)
	require.NoError(t, db.Create(&model.Software{
		ID: "sw-2", HostID: "host-1", Name: "example.com/mod",
		Version: "v2.1.0", PURL: "pkg:golang/example.com%2Fmod@v2.1.0",
	}).Error)

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts([]string{"host-1"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Patched, "已存在高于修复版的版本，应判 patched")
	assert.Equal(t, 0, result.Vanished)
}

// 主机数超过单批大小时必须全部处理完，不能只处理第一批。
//
// 分批实现最容易出的错是「只跑了第一批就返回」，而这在结果里表现为
// scanned 数偏小——没人会去核对这个数字，于是漏掉的主机永远不会被发现。
func TestReconcileHosts_AcrossBatches_ProcessesAll(t *testing.T) {
	db := setupReconcileTestDB(t)

	const hostCount = HostBatchSize + 37 // 跨两批，且第二批不是整批
	for i := range hostCount {
		hostID := fmt.Sprintf("host-%03d", i)
		vuln := model.Vulnerability{
			CveID:        fmt.Sprintf("CVE-2026-5%04d", i),
			Severity:     "high",
			PURL:         "pkg:golang/example.com%2Fmod@v1.0.0",
			FixedVersion: "v2.0.0",
		}
		require.NoError(t, db.Create(&vuln).Error)
		require.NoError(t, db.Create(&model.HostVulnerability{
			VulnID: vuln.ID, HostID: hostID,
			CurrentVersion: "v1.0.0", Status: model.HostVulnStatusUnpatched,
		}).Error)
		// 每台都已升到修复版之上
		require.NoError(t, db.Create(&model.Software{
			ID: fmt.Sprintf("sw-%03d", i), HostID: hostID,
			Name: "example.com/mod", Version: "v2.1.0",
			PURL: "pkg:golang/example.com%2Fmod@v2.1.0",
		}).Error)
	}

	hostIDs := make([]string, hostCount)
	for i := range hostIDs {
		hostIDs[i] = fmt.Sprintf("host-%03d", i)
	}

	rec := NewVulnReconciler(db, zap.NewNop())
	result, err := rec.ReconcileHosts(hostIDs)
	require.NoError(t, err)

	assert.Equal(t, hostCount, result.Scanned, "跨批次的主机必须全部被处理")
	assert.Equal(t, hostCount, result.Patched, "每台都已升级，应全部判 patched")
	assert.Equal(t, 0, result.Vanished)
}
