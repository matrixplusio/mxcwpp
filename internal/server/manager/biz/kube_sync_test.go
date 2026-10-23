package biz

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupKubeSyncDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	// AutoMigrate 在 sqlite 上会因 MySQL 方言（ON UPDATE）失败，按模型字段建一张宽松的表即可。
	for _, m := range []any{&model.KubeCluster{}, &model.KubeAlarm{}, &model.KubeWhitelist{}} {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(m); err != nil {
			t.Fatal(err)
		}
		cols := []string{}
		for _, f := range stmt.Schema.Fields {
			if f.DBName == "" {
				continue
			}
			if f.DBName == "id" {
				cols = append(cols, "id INTEGER PRIMARY KEY AUTOINCREMENT")
				continue
			}
			if strings.Contains(f.FieldType.String(), "Time") {
				cols = append(cols, f.DBName+" DATETIME") // 驱动按声明类型解析时间
				continue
			}
			cols = append(cols, f.DBName)
		}
		if err := db.Exec("CREATE TABLE " + stmt.Schema.Table + " (" + strings.Join(cols, ", ") + ")").Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// 连不上的集群：第一轮只标 offline，连续第二轮才告警；之后继续失败只累加计数，不重复建行。
func TestUnreachableClusterAlarmsAfterConsecutiveFailures(t *testing.T) {
	db := setupKubeSyncDB(t)
	c := model.KubeCluster{Name: "c1", KubeConfig: "not-a-kubeconfig", Status: model.KubeClusterStatusRunning}
	if err := db.Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	s := NewKubeSyncService(db, zap.NewNop(), NewKubeClientManager(db, zap.NewNop()), kube.NewKubeAlarmService(db, zap.NewNop()))

	count := func() (rows int64, hits int) {
		var alarms []model.KubeAlarm
		db.Where("alarm_type = ?", model.KubeAlarmTypeClusterUnreachable).Find(&alarms)
		for _, a := range alarms {
			hits += a.Count
		}
		return int64(len(alarms)), hits
	}

	s.syncCluster(c)
	var got model.KubeCluster
	db.First(&got, c.ID)
	if got.Status != model.KubeClusterStatusOffline {
		t.Fatalf("同步失败应标记 offline，实际 %q", got.Status)
	}
	if n, _ := count(); n != 0 {
		t.Fatalf("单次失败不应告警，实际 %d 条", n)
	}

	s.syncCluster(c)
	s.syncCluster(c)
	if n, hits := count(); n != 1 || hits != 2 {
		t.Fatalf("连续失败应只有 1 条告警并累加计数，实际 %d 条 / 计数 %d", n, hits)
	}
}
