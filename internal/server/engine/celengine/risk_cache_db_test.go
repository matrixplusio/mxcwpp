package celengine

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupRiskCacheDB 内存 sqlite + 手建表（避 MySQL 特有语法），供 reload 集成测使用。
func setupRiskCacheDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.Exec(`CREATE TABLE hosts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		host_id TEXT PRIMARY KEY,
		criticality TEXT,
		created_at TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id TEXT,
		category TEXT,
		status TEXT,
		last_seen_at TIMESTAMP
	)`)
	return db
}

// TestReloadAssetWeightCacheFromDB 验证 reload 真从 hosts 表加载 criticality 并映射为权重快照。
func TestReloadAssetWeightCacheFromDB(t *testing.T) {
	db := setupRiskCacheDB(t)
	db.Exec(`INSERT INTO hosts(host_id, criticality) VALUES ('h1','critical'),('h2','low'),('h3','')`)
	g := &AlertGenerator{db: db, log: zap.NewNop()}

	g.reloadAssetWeightCache()

	cases := map[string]float64{"h1": 1.3, "h2": 0.8, "h3": 1.0, "missing": 1.0}
	for host, want := range cases {
		if got := g.assetWeight(host); got != want {
			t.Errorf("assetWeight(%q)=%v, want %v", host, got, want)
		}
	}
}

// TestReloadCorrelationBoostCacheFromDB 验证 reload 聚合 host×近1h活跃告警的 distinct category 数并映射加权。
func TestReloadCorrelationBoostCacheFromDB(t *testing.T) {
	db := setupRiskCacheDB(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour) // 窗口外
	ins := func(host, cat, status string, ts time.Time) {
		db.Exec(`INSERT INTO alerts(host_id, category, status, last_seen_at) VALUES (?,?,?,?)`, host, cat, status, ts)
	}
	// h1: 3 类活跃 → 1.5
	ins("h1", "a", "active", now)
	ins("h1", "b", "active", now)
	ins("h1", "c", "active", now)
	// h2: 2 类活跃 → 1.2
	ins("h2", "a", "active", now)
	ins("h2", "b", "active", now)
	// h3: 1 类活跃（同类多条）→ 1.0
	ins("h3", "a", "active", now)
	ins("h3", "a", "active", now)
	// h4: 已解决，不计
	ins("h4", "a", "resolved", now)
	// h5: 活跃但在窗口外，不计
	ins("h5", "a", "active", old)

	g := &AlertGenerator{db: db, log: zap.NewNop()}
	g.reloadCorrelationBoostCache()

	cases := map[string]float64{"h1": 1.5, "h2": 1.2, "h3": 1.0, "h4": 1.0, "h5": 1.0, "missing": 1.0}
	for host, want := range cases {
		if got := g.correlationBoost(host); got != want {
			t.Errorf("correlationBoost(%q)=%v, want %v", host, got, want)
		}
	}
}
