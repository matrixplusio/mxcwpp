package migration

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupBehaviorAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.BehaviorAlert{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

// upsertOne 复刻 router.evaluateBDE 的 1d upsert 落库语义(便于在 sqlite 上验证去重契约)。
func upsertOne(db *gorm.DB, hostID, metric string, hit int) error {
	ba := model.BehaviorAlert{HostID: hostID, TenantID: "t-default", Metric: metric, Status: "open", HitCount: 1}
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "tenant_id"}, {Name: "host_id"}, {Name: "metric"}},
		DoUpdates: clause.Assignments(map[string]any{
			"z_score":   float64(hit),
			"hit_count": gorm.Expr("hit_count + 1"),
		}),
	}).Create(&ba).Error
}

// TestBehaviorAlertUpsertDedup 校验 1d：唯一索引 + OnConflict upsert 让同 (host, metric)
// 复发只累加 hit_count，不新增行。
func TestBehaviorAlertUpsertDedup(t *testing.T) {
	db := setupBehaviorAlertDB(t)
	logger := zap.NewNop()

	// migration 建唯一索引(sqlite 分支跳过存量去重，只建索引)。
	if err := migrateBehaviorAlertDedup(db, logger); err != nil {
		t.Fatalf("migrate dedup: %v", err)
	}
	if !db.Migrator().HasIndex(&model.BehaviorAlert{}, behaviorAlertDedupIndex) {
		t.Fatal("唯一索引未创建")
	}
	// 幂等：重复调用不报错。
	if err := migrateBehaviorAlertDedup(db, logger); err != nil {
		t.Fatalf("migrate dedup 二次: %v", err)
	}

	// 同 (host, metric) upsert 3 次 → 1 行，hit_count=3。
	for i := range 3 {
		if err := upsertOne(db, "host-a", "net_connect_count", i); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	// 不同 metric → 新行。
	if err := upsertOne(db, "host-a", "dns_query_count", 0); err != nil {
		t.Fatalf("upsert other metric: %v", err)
	}

	var rows []model.BehaviorAlert
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("期望 2 行(去重后), 实得 %d", len(rows))
	}
	var netRow model.BehaviorAlert
	if err := db.Where("host_id = ? AND metric = ?", "host-a", "net_connect_count").First(&netRow).Error; err != nil {
		t.Fatalf("load net row: %v", err)
	}
	if netRow.HitCount != 3 {
		t.Errorf("hit_count = %d, 期望 3", netRow.HitCount)
	}
}
