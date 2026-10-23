package advisory

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newDispositionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.Exec(`CREATE TABLE host_vulnerabilities (
		tenant_id TEXT DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vuln_id INTEGER NOT NULL,
		host_id TEXT NOT NULL,
		hostname TEXT,
		ip TEXT,
		current_version TEXT,
		matched_component TEXT,
		matched_fixed_version TEXT,
		status TEXT NOT NULL DEFAULT 'unpatched',
		patched_at DATETIME,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func seedHostVuln(t *testing.T, db *gorm.DB, vulnID uint, hostID, status string) {
	t.Helper()
	if err := db.Exec(
		`INSERT INTO host_vulnerabilities (vuln_id, host_id, current_version, status)
		 VALUES (?, ?, '1.0.0', ?)`, vulnID, hostID, status).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func statusOf(t *testing.T, db *gorm.DB, vulnID uint, hostID string) string {
	t.Helper()
	var s string
	if err := db.Raw(`SELECT status FROM host_vulnerabilities WHERE vuln_id = ? AND host_id = ?`,
		vulnID, hostID).Scan(&s).Error; err != nil {
		t.Fatalf("read status: %v", err)
	}
	return s
}

// TestReopenIfPreviouslyResolved_KeepsHumanDisposition 人工研判结论必须熬过同步。
//
// advisory 同步每 4 小时跑一轮，原实现用 Assign 无条件写 status='unpatched'，
// 而 GORM 的 Assign 在命中已有记录时同样生效——用户判过的误报、手动忽略的漏洞，
// 四小时后原样复活。判到最后没人再判，漏洞台账就失去意义。
func TestReopenIfPreviouslyResolved_KeepsHumanDisposition(t *testing.T) {
	db := newDispositionDB(t)
	c := &Coordinator{db: db, logger: zap.NewNop()}

	for _, st := range []string{
		model.HostVulnStatusIgnored,
		model.HostVulnStatusFalsePositive,
	} {
		seedHostVuln(t, db, 1, "host-"+st, st)
		c.reopenIfPreviouslyResolved(1, "host-"+st)
		if got := statusOf(t, db, 1, "host-"+st); got != st {
			t.Errorf("人工处置 %q 被同步改写为 %q", st, got)
		}
	}
}

// TestReopenIfPreviouslyResolved_ReopensSystemResolved 系统自行判定的"已修复/包消失"
// 在重新检出时必须翻回来，否则真实回归会被漏掉。
func TestReopenIfPreviouslyResolved_ReopensSystemResolved(t *testing.T) {
	db := newDispositionDB(t)
	c := &Coordinator{db: db, logger: zap.NewNop()}

	for _, st := range []string{
		model.HostVulnStatusPatched,
		model.HostVulnStatusVanished,
	} {
		host := "host-" + st
		seedHostVuln(t, db, 2, host, st)
		c.reopenIfPreviouslyResolved(2, host)
		if got := statusOf(t, db, 2, host); got != model.HostVulnStatusResurfaced {
			t.Errorf("状态 %q 重新检出后应为 %q，实际 %q",
				st, model.HostVulnStatusResurfaced, got)
		}
	}
}

// TestReopenIfPreviouslyResolved_LeavesOpenStatesAlone 待修复/已回归本就是开放态，
// 不需要也不应被再次改写。
func TestReopenIfPreviouslyResolved_LeavesOpenStatesAlone(t *testing.T) {
	db := newDispositionDB(t)
	c := &Coordinator{db: db, logger: zap.NewNop()}

	for _, st := range []string{
		model.HostVulnStatusUnpatched,
		model.HostVulnStatusResurfaced,
	} {
		host := "host-" + st
		seedHostVuln(t, db, 3, host, st)
		c.reopenIfPreviouslyResolved(3, host)
		if got := statusOf(t, db, 3, host); got != st {
			t.Errorf("开放态 %q 被改写为 %q", st, got)
		}
	}
}
