package policy

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec("CREATE TABLE system_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, `key` TEXT, value TEXT, category TEXT, description TEXT, created_at DATETIME, updated_at DATETIME)").Error; err != nil {
		t.Fatal(err)
	}
	return db
}

// 数据库为空：用配置文件的值初始化并写入数据库，之后以数据库为准。
func TestSeedsFromConfigFileOnce(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{}
	cfg.MTLS.IdentityConflict = "reject"
	s := New(db, cfg, zap.NewNop())
	if got := s.Get(); got.IdentityConflict != "reject" || got.AutoUpdate {
		t.Fatalf("应按配置文件初始化，实际 %+v", got)
	}
	stored, found, err := model.LoadAgentPolicy(db)
	if err != nil || !found || stored.IdentityConflict != "reject" {
		t.Fatalf("初始化后应写入数据库，实际 %+v found=%v err=%v", stored, found, err)
	}
}

// 数据库已有策略：以数据库为准，配置文件不再生效（重新渲染配置文件不能把控制台设置覆盖回去）。
func TestDatabaseWinsOverConfigFile(t *testing.T) {
	db := testDB(t)
	if err := model.SaveAgentPolicy(db, model.AgentPolicy{IdentityConflict: "reject"}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.MTLS.IdentityConflict = "alert"
	cfg.Agent.AutoUpdate = true
	got := New(db, cfg, zap.NewNop()).Get()
	if got.IdentityConflict != "reject" || got.AutoUpdate {
		t.Fatalf("应以数据库为准，实际 %+v", got)
	}
}

// 控制台改动在刷新间隔后生效；数据库里出现非法值时沿用上一次的有效值。
func TestRefreshPicksUpChangesAndIgnoresInvalid(t *testing.T) {
	db := testDB(t)
	s := New(db, &config.Config{}, zap.NewNop())

	if err := model.SaveAgentPolicy(db, model.AgentPolicy{IdentityConflict: "reject", AutoUpdate: true}); err != nil {
		t.Fatal(err)
	}
	s.loadedAt = time.Now().Add(-refreshInterval)
	if got := s.Get(); got.IdentityConflict != "reject" || !got.AutoUpdate {
		t.Fatalf("刷新后应生效，实际 %+v", got)
	}

	db.Exec("UPDATE system_configs SET value = ?", `{"identity_conflict":"bogus"}`)
	s.loadedAt = time.Now().Add(-refreshInterval)
	if got := s.Get(); got.IdentityConflict != "reject" {
		t.Fatalf("非法值不应生效，应沿用上一次的有效值，实际 %+v", got)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	if err := model.SaveAgentPolicy(testDB(t), model.AgentPolicy{IdentityConflict: "drop"}); err == nil {
		t.Fatal("非法取值应拒绝保存")
	}
}
