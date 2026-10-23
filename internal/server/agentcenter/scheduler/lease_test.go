package scheduler

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newLeaseDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.Exec(`CREATE TABLE scheduler_leases (tenant_id TEXT DEFAULT 't-default',
		name TEXT PRIMARY KEY, holder TEXT NOT NULL, expires_at DATETIME NOT NULL)`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

// TestLease_SingleHolderAndTakeover 同一时刻只有一台持有；持有者停止续期、租约过期后另一台接手。
func TestLease_SingleHolderAndTakeover(t *testing.T) {
	db := newLeaseDB(t)
	now := time.Now()
	a := NewLease(db, "agent_update", "ac-a", 30*time.Second, zap.NewNop())
	b := NewLease(db, "agent_update", "ac-b", 30*time.Second, zap.NewNop())
	a.now = func() time.Time { return now }
	b.now = func() time.Time { return now }

	if !a.Hold() {
		t.Fatal("a 应取得租约")
	}
	if b.Hold() {
		t.Fatal("租约未过期时 b 不应取得")
	}
	if !a.Hold() {
		t.Fatal("a 应能续期")
	}

	// a 停止续期，时间走过 ttl
	later := now.Add(31 * time.Second)
	b.now = func() time.Time { return later }
	if !b.Hold() {
		t.Fatal("租约过期后 b 应接手")
	}
	a.now = func() time.Time { return later }
	if a.Hold() {
		t.Fatal("被接手后 a 不应再持有")
	}
}

type fakeInstance struct {
	id      string
	standby bool
}

func (f fakeInstance) InstanceID() string { return f.id }
func (f fakeInstance) Standby() bool      { return f.standby }

// TestLease_StandbyNeverHolds 备用 AC 不参与租约：主 AC 升级期间它若接了租约会一直续期占着，
// 升级完推送全落在没有安装包的那台上。
func TestLease_StandbyNeverHolds(t *testing.T) {
	db := newLeaseDB(t)
	if l := newLeaseUnlessStandby(db, "agent_update", fakeInstance{"ac-b", true}, time.Minute, zap.NewNop()); l != nil {
		t.Fatal("备用实例不应创建租约")
	}
	if l := newLeaseUnlessStandby(db, "agent_update", fakeInstance{"ac-a", false}, time.Minute, zap.NewNop()); l == nil || !l.Hold() {
		t.Fatal("主实例应能取得租约")
	}
}
