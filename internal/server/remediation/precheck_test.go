package remediation

import (
	"strconv"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupPreCheckDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, _ := db.DB(); sqlDB != nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(&model.Vulnerability{}, &model.HostVulnerability{}, &model.RemediationTask{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedHostVuln(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	if err := db.Create(&model.Vulnerability{ID: 1, CveID: "CVE-2026-1", Component: "glibc", Status: "unpatched"}).Error; err != nil {
		t.Fatalf("create vuln: %v", err)
	}
	hv := model.HostVulnerability{VulnID: 1, HostID: "host-1", Status: model.HostVulnStatusUnpatched}
	if err := db.Create(&hv).Error; err != nil {
		t.Fatalf("create host vuln: %v", err)
	}
	return hv.ID
}

// TestPreCheck_NotInstalledClosesUnpatched 验证 agent 实时 pre-check 判 not_installed
// (漏洞版本不在=已升级/已删) → 普通 unpatched host_vuln 自动对账关闭为 patched，
// 修复"software 库存陈旧致已打补丁漏洞仍报"的核心。
func TestPreCheck_NotInstalledClosesUnpatched(t *testing.T) {
	db := setupPreCheckDB(t)
	hvID := seedHostVuln(t, db)
	h := NewPreCheckResultHandler(db, zap.NewNop())

	err := h.HandleResult("host-1", map[string]string{
		"host_vuln_id": itoa(hvID),
		"status":       model.PreCheckStatusNotInstalled,
		"message":      "已升级",
	})
	if err != nil {
		t.Fatalf("HandleResult: %v", err)
	}

	var hv model.HostVulnerability
	db.First(&hv, hvID)
	if hv.Status != model.HostVulnStatusPatched {
		t.Fatalf("status = %q, want patched", hv.Status)
	}
	if hv.PatchedReason != model.PatchedReasonPreCheckVerified {
		t.Fatalf("patched_reason = %q, want precheck_verified", hv.PatchedReason)
	}
}

// TestPreCheck_AvailableKeepsUnpatched 验证 available(仍有可升级版=仍有洞)不误关。
func TestPreCheck_AvailableKeepsUnpatched(t *testing.T) {
	db := setupPreCheckDB(t)
	hvID := seedHostVuln(t, db)
	h := NewPreCheckResultHandler(db, zap.NewNop())

	if err := h.HandleResult("host-1", map[string]string{
		"host_vuln_id": itoa(hvID),
		"status":       model.PreCheckStatusAvailable,
	}); err != nil {
		t.Fatalf("HandleResult: %v", err)
	}

	var hv model.HostVulnerability
	db.First(&hv, hvID)
	if hv.Status != model.HostVulnStatusUnpatched {
		t.Fatalf("status = %q, want unpatched (available=仍有洞不该关)", hv.Status)
	}
}

func itoa(u uint) string {
	return strconv.FormatUint(uint64(u), 10)
}
