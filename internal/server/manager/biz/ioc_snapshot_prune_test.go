package biz

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 只留最近 iocSnapshotKeep 份；不足时不删。
// 旧写法在 MySQL 上直接报错且错误被忽略，一份都没删过——这里钉住「确实删了、留的是最新的」。
func TestPruneSnapshots(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.IOCSnapshot{}); err != nil {
		t.Fatal(err)
	}
	ti := &ThreatIntel{db: db, logger: zap.NewNop()}

	for i := 0; i < iocSnapshotKeep-1; i++ {
		db.Create(&model.IOCSnapshot{Version: "v"})
	}
	ti.pruneSnapshots()
	var n int64
	db.Model(&model.IOCSnapshot{}).Count(&n)
	if n != int64(iocSnapshotKeep-1) {
		t.Fatalf("不足 %d 份时不应删除，剩 %d", iocSnapshotKeep, n)
	}

	for i := 0; i < 6; i++ {
		db.Create(&model.IOCSnapshot{Version: "v"})
	}
	ti.pruneSnapshots()
	var ids []uint
	db.Model(&model.IOCSnapshot{}).Order("id").Pluck("id", &ids)
	total := uint(iocSnapshotKeep - 1 + 6)
	if len(ids) != iocSnapshotKeep || ids[len(ids)-1] != total || ids[0] != total-uint(iocSnapshotKeep)+1 {
		t.Errorf("应留最新的 %d 份，得 %v", iocSnapshotKeep, ids)
	}
}
