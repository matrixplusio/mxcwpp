package celengine

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupStageDB 内存 sqlite + 手建表（alerts 的时间列带 MySQL 特有语法，不能 AutoMigrate）。
func setupStageDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		result_id TEXT, host_id TEXT, rule_id TEXT, policy_id TEXT,
		source TEXT, severity TEXT, risk_score REAL, category TEXT,
		title TEXT, description TEXT, actual TEXT, expected TEXT,
		fix_suggestion TEXT, status TEXT, mode TEXT,
		would_action TEXT, action TEXT, action_result TEXT,
		last_notified_at TIMESTAMP, resolved_at TIMESTAMP,
		resolved_by TEXT, resolve_reason TEXT,
		attck_tactic TEXT, attck_technique TEXT,
		hit_count INTEGER DEFAULT 1, notify_count INTEGER DEFAULT 0,
		first_seen_at TIMESTAMP, last_seen_at TIMESTAMP,
		created_at TIMESTAMP, updated_at TIMESTAMP
	)`).Error; err != nil {
		t.Fatalf("create alerts: %v", err)
	}
	if err := db.AutoMigrate(&model.RuleShadowStat{}); err != nil {
		t.Fatalf("migrate shadow stats: %v", err)
	}
	return db
}

func newStageGenerator(db *gorm.DB) *AlertGenerator {
	g := &AlertGenerator{
		db:        db,
		log:       zap.NewNop(),
		throttler: NewHitThrottler(defaultHitBurstThreshold, defaultHitRefillWindow, defaultHitThrottleCapacity),
	}
	g.shadow = newShadowRecorder(db, zap.NewNop())
	empty := []model.AlertWhitelist{}
	g.dbWhitelist.Store(&empty)
	hosts := map[string]time.Time{}
	g.hostCreatedAt.Store(&hosts)
	weights := map[string]float64{}
	g.assetWeightCache.Store(&weights)
	boosts := map[string]float64{}
	g.correlationBoostCache.Store(&boosts)
	return g
}

func countAlerts(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Table("alerts").Count(&n).Error; err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

// 影子阶段的规则命中不产生告警——这是整个生命周期机制的前提。
// 若影子规则照样告警，那么"先观察再放开"就只是一句说辞。
func TestShadowRuleProducesNoAlert(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)

	rule := model.DetectionRule{
		Name: "shadow rule", Severity: "high",
		Stage: model.RuleStageShadow, Fidelity: model.RuleFidelityHigh,
	}
	rule.ID = 42
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})

	if n := countAlerts(t, db); n != 0 {
		t.Fatalf("影子规则不该产生告警，实际写入 %d 条", n)
	}
}

// 影子命中必须被记录下来，否则它永远凑不齐晋级所需的观察数据，
// 会被永久卡在影子阶段——不可观测的观察期等于没有观察期。
func TestShadowHitIsRecorded(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)

	rule := model.DetectionRule{
		Name: "shadow rule", Severity: "high",
		Stage: model.RuleStageShadow, Fidelity: model.RuleFidelityHigh,
	}
	rule.ID = 43
	for range 3 {
		g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})
	}
	g.Generate("h2", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})
	g.shadow.flush()

	var stat model.RuleShadowStat
	if err := db.Where("rule_id = ?", "cel-43").First(&stat).Error; err != nil {
		t.Fatalf("影子命中未落库: %v", err)
	}
	if stat.Hits != 4 {
		t.Fatalf("命中数应为 4，实际 %d", stat.Hits)
	}
	if stat.Hosts != 2 {
		t.Fatalf("命中主机数应为 2，实际 %d", stat.Hosts)
	}
}

// 多轮落库要累加而不是覆盖：覆盖会让长期观察永远停在最后一轮的数字上，
// 使日均命中被严重低估，噪声规则因而蒙混过关。
func TestShadowHitsAccumulateAcrossFlushes(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)

	rule := model.DetectionRule{
		Name: "shadow rule", Severity: "high",
		Stage: model.RuleStageShadow, Fidelity: model.RuleFidelityHigh,
	}
	rule.ID = 44
	for range 2 {
		g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})
	}
	g.shadow.flush()
	for range 5 {
		g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})
	}
	g.shadow.flush()

	var stat model.RuleShadowStat
	if err := db.Where("rule_id = ?", "cel-44").First(&stat).Error; err != nil {
		t.Fatalf("影子命中未落库: %v", err)
	}
	if stat.Hits != 7 {
		t.Fatalf("跨轮次命中应累加为 7，实际 %d", stat.Hits)
	}
}

// context 阶段同样不独立告警：它的命中只作为关联信号参与事件聚合。
func TestContextRuleProducesNoAlert(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)

	rule := model.DetectionRule{
		Name: "context rule", Severity: "high",
		Stage: model.RuleStageContext, Fidelity: model.RuleFidelityHigh,
	}
	rule.ID = 45
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})

	if n := countAlerts(t, db); n != 0 {
		t.Fatalf("context 规则不该独立告警，实际写入 %d 条", n)
	}
}

// 存量规则（stage 为空，尚未回填）必须照常告警。
//
// 这是升级路径上最危险的一格：如果空值被当成"未晋级"，那么一次升级就会让
// 所有已部署规则集体失声，而平台表面上一切正常。
func TestEmptyStageStillAlerts(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)

	rule := model.DetectionRule{
		Name: "legacy rule", Severity: "high",
		Stage: "", Fidelity: model.RuleFidelityHigh,
	}
	rule.ID = 46
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/bin/sh"})

	if n := countAlerts(t, db); n == 0 {
		t.Fatal("未回填 stage 的存量规则必须保持原有告警行为，否则升级即失声")
	}
}
