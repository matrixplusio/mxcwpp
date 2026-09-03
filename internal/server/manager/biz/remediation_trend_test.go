package biz

import (
	"testing"
	"time"
)

// TestGetRemediationTrend_InstanceLevel 验证修复趋势走 host_vulnerabilities（实例级），
// 与顶部卡片同源，且绝不读 vulnerabilities 表的 CVE 级 discovered_at/status/patched_at。
//
// 陷阱数据：插入 2 条 vulnerabilities（CVE 级 status=patched + patched_at 今天，但
// discovered_at 为 NULL）。旧实现读 vulnerabilities → discovered=0、patched=2，与实例
// 级卡片打架。新实现读 host_vulnerabilities → discovered=3、patched=1。
func TestGetRemediationTrend_InstanceLevel(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	svc := &RemediationService{db: db, logger: nopLogger()}

	today := time.Now().Format("2006-01-02 15:04:05")

	// CVE 级陷阱：2 条 vulnerabilities 均标 patched（全队列修好口径），discovered_at 留空
	if err := db.Exec(
		`INSERT INTO vulnerabilities (cve_id, severity, status, patched_at, discovered_at)
		 VALUES ('CVE-2026-1001','high','patched',?,NULL),
		        ('CVE-2026-1002','high','patched',?,NULL)`,
		today, today).Error; err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}

	// 实例级真相：3 条 host_vuln 今天检出，其中 1 条今天修复
	if err := db.Exec(
		`INSERT INTO host_vulnerabilities (vuln_id, host_id, status, patched_at, created_at)
		 VALUES (1,'h1','unpatched',NULL,?),
		        (1,'h2','patched',?,?),
		        (2,'h3','unpatched',NULL,?)`,
		today, today, today, today).Error; err != nil {
		t.Fatalf("seed host_vulnerabilities: %v", err)
	}

	trend, err := svc.GetRemediationTrend(30)
	if err != nil {
		t.Fatalf("GetRemediationTrend: %v", err)
	}

	var discovered, patched int64
	for _, d := range trend {
		discovered += d.Discovered
		patched += d.Patched
	}

	// 实例级口径：检出 = 3 条 host_vuln（非 vulnerabilities 的 discovered_at=0）
	if discovered != 3 {
		t.Errorf("discovered = %d, want 3 (host_vuln created_at, not CVE discovered_at)", discovered)
	}
	// 实例级口径：修复 = 1 条 host_vuln patched（非 2 条 CVE 级 vulnerabilities.patched）
	if patched != 1 {
		t.Errorf("patched = %d, want 1 (host_vuln patched, not CVE-level vulnerabilities.patched)", patched)
	}
}
