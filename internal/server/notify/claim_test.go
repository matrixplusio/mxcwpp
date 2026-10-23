package notify

import (
	"sync"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newClaimDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// sqlite :memory: 每条连接是各自独立的库，并发时新连接会看到空库。
	// 限单连接，让并发占用真正落在同一份数据上。
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	// 手写建表：model.Alert 带 MySQL 专属的 ON UPDATE CURRENT_TIMESTAMP，
	// sqlite 无法解析，AutoMigrate 会失败。这里只需要占用逻辑用到的几列。
	if err := db.Exec(`CREATE TABLE alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id TEXT DEFAULT 't-default',
		result_id TEXT,
		host_id TEXT,
		rule_id TEXT,
		severity TEXT,
		title TEXT,
		status TEXT,
		last_notified_at DATETIME,
		notify_count INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

// seedAlert 用原生 SQL 插入，避开 model.Alert 的 MySQL 专属列定义。
func seedAlert(t *testing.T, db *gorm.DB, lastNotified *time.Time) uint {
	t.Helper()
	if err := db.Exec(
		`INSERT INTO alerts (result_id, host_id, rule_id, severity, title, status, last_notified_at, notify_count)
		 VALUES (?, 'h-1', 'rule-1', 'critical', 'test', 'active', ?, 0)`,
		"r-"+t.Name(), lastNotified).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	var id uint
	if err := db.Raw(`SELECT id FROM alerts ORDER BY id DESC LIMIT 1`).Scan(&id).Error; err != nil {
		t.Fatalf("read id: %v", err)
	}
	return id
}

// notifyCountOf 读取当前通知次数。
func notifyCountOf(t *testing.T, db *gorm.DB, id uint) int {
	t.Helper()
	var n int
	if err := db.Raw(`SELECT notify_count FROM alerts WHERE id = ?`, id).Scan(&n).Error; err != nil {
		t.Fatalf("read notify_count: %v", err)
	}
	return n
}

// TestClaim_OnlyOnceForNewAlert 从未通知过的告警只能被占用一次。
//
// 这正是原先的竞态：AgentCenter 内联通知的 goroutine 尚未写回 last_notified_at 时，
// Manager 定时器扫到 IS NULL 会把同一条再发一次，值班收到两遍。
func TestClaim_OnlyOnceForNewAlert(t *testing.T) {
	db := newClaimDB(t)
	id := seedAlert(t, db, nil)

	first, err := ClaimAlertNotification(db, id, time.Now())
	if err != nil || !first {
		t.Fatalf("首次占用应成功: claimed=%v err=%v", first, err)
	}
	second, err := ClaimAlertNotification(db, id, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Error("已被占用的告警不应再次占用成功（会导致重复通知）")
	}
}

// TestClaim_ConcurrentSingleWinner 并发占用只有一个赢家，计数只加一次。
func TestClaim_ConcurrentSingleWinner(t *testing.T) {
	db := newClaimDB(t)
	id := seedAlert(t, db, nil)

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	notBefore := time.Now()
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ok, err := ClaimAlertNotification(db, id, notBefore)
			if err != nil {
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Errorf("并发占用应只有 1 个赢家，实际 %d", wins)
	}
	if got := notifyCountOf(t, db, id); got != 1 {
		t.Errorf("notify_count = %d, want 1", got)
	}
}

// TestClaim_ReclaimAfterInterval 周期重复提醒：上次通知早于 cutoff 时可再次占用。
// 这条同时保证发送失败不会永久丢失——下个周期会重新可占。
func TestClaim_ReclaimAfterInterval(t *testing.T) {
	db := newClaimDB(t)
	old := time.Now().Add(-2 * time.Hour)
	id := seedAlert(t, db, &old)

	cutoff := time.Now().Add(-time.Hour)
	ok, err := ClaimAlertNotification(db, id, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("上次通知早于 cutoff，应可重新占用")
	}
}

// TestClaim_NotYetDue 上次通知晚于 cutoff 时不得占用，避免提前重复打扰。
func TestClaim_NotYetDue(t *testing.T) {
	db := newClaimDB(t)
	recent := time.Now().Add(-5 * time.Minute)
	id := seedAlert(t, db, &recent)

	cutoff := time.Now().Add(-time.Hour)
	ok, err := ClaimAlertNotification(db, id, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("上次通知晚于 cutoff，不应占用成功")
	}
}
