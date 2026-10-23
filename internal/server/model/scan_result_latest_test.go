package model

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func latestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE scan_results (
		tenant_id TEXT DEFAULT 't-default', task_id TEXT, host_id TEXT, rule_id TEXT,
		hostname TEXT, policy_id TEXT, policy_name TEXT, status TEXT, severity TEXT, category TEXT,
		title TEXT, actual TEXT, expected TEXT, fix_suggestion TEXT,
		checked_at DATETIME, created_at DATETIME, is_latest BOOLEAN NOT NULL DEFAULT 0,
		PRIMARY KEY (task_id, host_id, rule_id))`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func writeResult(t *testing.T, db *gorm.DB, task string, checked time.Time) {
	t.Helper()
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&ScanResult{TaskID: task, HostID: "h1", RuleID: "r1", Status: ResultStatusFail, CheckedAt: LocalTime(checked)}).Error; err != nil {
			return err
		}
		return MarkLatestScanResult(tx, "h1", "r1")
	})
	if err != nil {
		t.Fatal(err)
	}
}

func latestTasks(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var tasks []string
	db.Model(&ScanResult{}).Where("is_latest = ?", true).Pluck("task_id", &tasks)
	return tasks
}

// 每主机每规则恰好一行最新；晚到的旧扫描结果不能顶掉更新的那行。
func TestMarkLatestScanResult(t *testing.T) {
	db := latestDB(t)
	now := time.Now()

	writeResult(t, db, "t1", now.Add(-2*time.Hour))
	writeResult(t, db, "t2", now)
	if got := latestTasks(t, db); len(got) != 1 || got[0] != "t2" {
		t.Fatalf("复扫后最新应为 t2，得 %v", got)
	}

	// 乱序到达：t3 的检查时间早于 t2
	writeResult(t, db, "t3", now.Add(-time.Hour))
	if got := latestTasks(t, db); len(got) != 1 || got[0] != "t2" {
		t.Errorf("晚到的旧结果不应成为最新，得 %v", got)
	}
}
