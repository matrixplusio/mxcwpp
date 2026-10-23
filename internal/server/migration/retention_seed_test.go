package migration

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupRetentionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.Exec(`CREATE TABLE retention_policies (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ch_table TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		description TEXT,
		retention_days INTEGER NOT NULL DEFAULT 30,
		updated_by TEXT,
		updated_at TIMESTAMP,
		created_at TIMESTAMP
	)`)
	return db
}

func daysFor(t *testing.T, db *gorm.DB, chTable string) int {
	t.Helper()
	var rp model.RetentionPolicy
	if err := db.Where("ch_table = ?", chTable).First(&rp).Error; err != nil {
		t.Fatalf("load %s: %v", chTable, err)
	}
	return rp.RetentionDays
}

// TestSeedRetentionReconcile 校验 seed 的默认值对齐语义:
//   - 缺失行 → 按默认值插入
//   - 已存在且 updated_by 空(内置未改) → 对齐到当前默认值(修 ebpf_events 7→30 这类)
//   - 已存在且 updated_by 非空(管理员改过) → 尊重自定义,不覆盖
func TestSeedRetentionReconcile(t *testing.T) {
	db := setupRetentionDB(t)

	// 旧的内置行:ebpf_events=7、从未管理员改动(updated_by 空)
	db.Exec(`INSERT INTO retention_policies(ch_table, retention_days, updated_by) VALUES ('ebpf_events', 7, '')`)
	// 管理员自定义行:audit_log=999、updated_by 非空
	db.Exec(`INSERT INTO retention_policies(ch_table, retention_days, updated_by) VALUES ('audit_log', 999, 'admin')`)

	SeedRetentionPolicies(db, zap.NewNop())

	// ebpf_events 未被管理员改 → 对齐到当前默认 30
	if got := daysFor(t, db, "ebpf_events"); got != 30 {
		t.Errorf("ebpf_events 应对齐默认 30, got %d", got)
	}
	// audit_log 管理员改过 → 保留 999,不被默认 180 覆盖
	if got := daysFor(t, db, "audit_log"); got != 999 {
		t.Errorf("audit_log 管理员自定义应保留 999, got %d", got)
	}
	// 缺失的内置行(如 fim_events)按默认插入
	if got := daysFor(t, db, "fim_events"); got != 30 {
		t.Errorf("fim_events 应按默认插入 30, got %d", got)
	}
}

// TestSyncRetentionTTLNilConn 校验 chConn 为 nil 时安全跳过(不 panic)。
func TestSyncRetentionTTLNilConn(t *testing.T) {
	db := setupRetentionDB(t)
	SyncRetentionTTL(context.TODO(), db, nil, zap.NewNop())
}
