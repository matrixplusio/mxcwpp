package migration

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupAnomalyAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AnomalyAlert{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

// TestAnomalyAlertDedupNormalizesLegacyNullKeys 校验历史 NULL 去重键会先归一化再合并，
// 且 last_seen_at 会回填，避免 MySQL UNIQUE 的 NULL 语义绕过去重与列表排序。
func TestAnomalyAlertDedupNormalizesLegacyNullKeys(t *testing.T) {
	db := setupAnomalyAlertDB(t)
	for range 2 {
		if err := db.Exec(`INSERT INTO anomaly_alerts
			(tenant_id, host_id, alert_type, pattern_name, top_metric, status, hit_count, created_at, updated_at)
			VALUES ('t-default', 'legacy-host', 'correlation', NULL, NULL, 'open', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).Error; err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
	}

	if err := migrateAnomalyAlertDedup(db, zap.NewNop()); err != nil {
		t.Fatalf("migrate dedup: %v", err)
	}
	var rows []model.AnomalyAlert
	if err := db.Where("host_id = ?", "legacy-host").Find(&rows).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("NULL 键归一化后应合并为 1 行，实得 %d", len(rows))
	}
	if rows[0].PatternName != "" || rows[0].TopMetric != "" || rows[0].HitCount != 2 {
		t.Fatalf("归一化/合并结果异常: pattern=%q top_metric=%q hit_count=%d",
			rows[0].PatternName, rows[0].TopMetric, rows[0].HitCount)
	}
	if time.Time(rows[0].LastSeenAt).IsZero() {
		t.Fatal("历史行 last_seen_at 应完成回填")
	}
}

// upsertAnomaly 复刻 Detector.upsertAnomaly 的去重语义（在 sqlite 上验证唯一索引 + OnConflict 契约）。
func upsertAnomalyForTest(db *gorm.DB, hostID, alertType, pattern, topMetric string) error {
	a := model.AnomalyAlert{
		TenantID: "t-default", HostID: hostID, AlertType: alertType,
		PatternName: pattern, TopMetric: topMetric, Status: "open", HitCount: 1,
	}
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "tenant_id"}, {Name: "host_id"}, {Name: "alert_type"},
			{Name: "pattern_name"}, {Name: "top_metric"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"hit_count": gorm.Expr("hit_count + 1"),
		}),
	}).Create(&a).Error
}

// TestAnomalyAlertUpsertDedup 校验：唯一索引 + OnConflict upsert 让同键复发只累加 hit_count 不新增行，
// 不同 pattern/top_metric 才新建行；migration 幂等。
func TestAnomalyAlertUpsertDedup(t *testing.T) {
	db := setupAnomalyAlertDB(t)
	logger := zap.NewNop()

	if err := migrateAnomalyAlertDedup(db, logger); err != nil {
		t.Fatalf("migrate dedup: %v", err)
	}
	if !db.Migrator().HasIndex(&model.AnomalyAlert{}, anomalyAlertDedupIndex) {
		t.Fatal("唯一索引未创建")
	}
	// 幂等：重复调用不报错、不重复建索引。
	if err := migrateAnomalyAlertDedup(db, logger); err != nil {
		t.Fatalf("migrate dedup 二次: %v", err)
	}

	// 同键 upsert 3 次 → 1 行，hit_count=3。
	for range 3 {
		if err := upsertAnomalyForTest(db, "host-a", "correlation", "c2_beacon", ""); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	// 不同 pattern → 新行。
	if err := upsertAnomalyForTest(db, "host-a", "correlation", "data_exfiltration", ""); err != nil {
		t.Fatalf("upsert other pattern: %v", err)
	}
	// 不同 top_metric（isolation_forest 路径）→ 新行。
	if err := upsertAnomalyForTest(db, "host-a", "isolation_forest", "", "net_connect_count"); err != nil {
		t.Fatalf("upsert forest: %v", err)
	}

	var rows []model.AnomalyAlert
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("期望 3 行(去重后), 实得 %d", len(rows))
	}
	var beacon model.AnomalyAlert
	if err := db.Where("host_id = ? AND alert_type = ? AND pattern_name = ?",
		"host-a", "correlation", "c2_beacon").First(&beacon).Error; err != nil {
		t.Fatalf("load beacon row: %v", err)
	}
	if beacon.HitCount != 3 {
		t.Errorf("hit_count=%d, 期望 3", beacon.HitCount)
	}
}
