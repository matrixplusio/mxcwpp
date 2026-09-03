package anomaly

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupAnomalyDB 建内存 sqlite + anomaly_alerts 表 + 去重唯一索引（upsert 依赖它）。
func setupAnomalyDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AnomalyAlert{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX " + anomalyAlertDedupIndex +
		" ON anomaly_alerts (tenant_id, host_id, alert_type, pattern_name, top_metric)").Error; err != nil {
		t.Fatalf("create dedup index: %v", err)
	}
	return db
}

// TestModeTransitionWaitsForAdmittedWrite 校验模式切换与真正 DB 写入之间有同步屏障：
// 已获准的在途写完成前 SetMode(off) 不会返回；一旦返回，后续写入必须被拒绝。
func TestModeTransitionWaitsForAdmittedWrite(t *testing.T) {
	db := setupAnomalyDB(t)
	d := NewDetector(db, nil, zap.NewNop())
	d.mu.Lock()
	d.schemaReady = true
	d.mu.Unlock()
	d.SetMode(ModeContext)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	if err := db.Callback().Create().Before("gorm:create").Register("test:block_anomaly_create", func(*gorm.DB) {
		once.Do(func() {
			close(entered)
			<-release
		})
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		d.persistAnomalyIfEligible(&model.AnomalyAlert{
			HostID: "h-race", AlertType: "isolation_forest", TopMetric: "net_connect_count", Status: "open",
		})
	}()
	<-entered

	modeDone := make(chan struct{})
	go func() {
		defer close(modeDone)
		d.SetMode(ModeOff)
	}()
	select {
	case <-modeDone:
		t.Fatal("SetMode(off) 不应越过仍在执行的已准入写入")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-writeDone
	<-modeDone

	if _, persisted := d.persistAnomalyIfEligible(&model.AnomalyAlert{
		HostID: "h-after-off", AlertType: "isolation_forest", TopMetric: "net_connect_count", Status: "open",
	}); persisted {
		t.Fatal("SetMode(off) 返回后不应再允许新写入")
	}
	var count int64
	if err := db.Model(&model.AnomalyAlert{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("应仅有切换前已准入的 1 行，实得 %d", count)
	}
}

// TestEmitForestAlertPersistGate 校验落库闸：off/shadow 只观测不落库，context（schema 就绪）才 upsert。
// 覆盖 Codex 关切的"SetMode 并发切 off 后快照仍 upsert"——off 必须零落库。
func TestEmitForestAlertPersistGate(t *testing.T) {
	db := setupAnomalyDB(t)
	d := NewDetector(db, nil, zap.NewNop())
	// schema 就绪，使 context/alert 具备落库资格。
	d.mu.Lock()
	d.schemaReady = true
	d.mu.Unlock()

	count := func() int64 {
		var n int64
		db.Model(&model.AnomalyAlert{}).Count(&n)
		return n
	}
	metrics := make([]float64, featureCount)

	// off：不落库。
	d.SetMode(ModeOff)
	d.emitForestAlert("h1", "host1", metrics, 0.9)
	if n := count(); n != 0 {
		t.Fatalf("off 模式应零落库，实得 %d 行", n)
	}

	// shadow：不落库。
	d.SetMode(ModeShadow)
	d.emitForestAlert("h1", "host1", metrics, 0.9)
	if n := count(); n != 0 {
		t.Fatalf("shadow 模式应零落库，实得 %d 行", n)
	}

	// context：落库。
	d.SetMode(ModeContext)
	d.emitForestAlert("h1", "host1", metrics, 0.9)
	if n := count(); n != 1 {
		t.Fatalf("context 模式应落库 1 行，实得 %d 行", n)
	}
}
