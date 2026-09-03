package scheduler

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestPluginUpdateSchedulerCheckAndBroadcast_EmptyTableDoesNotLogError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	if err := db.AutoMigrate(&model.PluginConfig{}); err != nil {
		t.Fatalf("failed to migrate plugin_configs: %v", err)
	}

	core, observed := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	scheduler := &PluginUpdateScheduler{
		db:            db,
		logger:        logger,
		lastCheckTime: time.Now(),
	}

	scheduler.checkAndBroadcast(context.Background())

	for _, entry := range observed.All() {
		if entry.Level == zap.ErrorLevel && entry.Message == "查询插件配置更新时间失败" {
			t.Fatalf("unexpected error log: %+v", entry)
		}
	}
}
