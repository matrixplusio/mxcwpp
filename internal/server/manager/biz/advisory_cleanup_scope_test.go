package biz

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// 进程启动后的第一轮清理走全量；之后一直只看增量，水位推进到上一轮开始时的最大 id。
// 周期性的全量不再由这里计时，改由定时任务调起。
func TestNextCleanupScope(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE host_vulnerabilities (id INTEGER PRIMARY KEY)`)
	db.Exec(`INSERT INTO host_vulnerabilities VALUES (100)`)
	c := &AdvisoryConsumer{db: db, logger: zap.NewNop()}
	t0 := time.Now()

	if sc := c.nextCleanupScopeLocked(t0); !sc.Full {
		t.Fatal("第一轮应走全量")
	}

	db.Exec(`INSERT INTO host_vulnerabilities VALUES (250)`)
	sc := c.nextCleanupScopeLocked(t0.Add(time.Minute))
	if sc.Full || sc.MinHostVulnID != 100 {
		t.Errorf("第二轮应是增量、水位 100，得 %+v", sc)
	}
	if !sc.VulnUpdatedSince.Before(t0) {
		t.Errorf("漏洞更新时间的起点应早于上一轮开始时刻（留余量），得 %v", sc.VulnUpdatedSince)
	}

	if sc := c.nextCleanupScopeLocked(t0.Add(2 * time.Minute)); sc.Full || sc.MinHostVulnID != 250 {
		t.Errorf("第三轮水位应推进到 250，得 %+v", sc)
	}
	if sc := c.nextCleanupScopeLocked(t0.Add(48 * time.Hour)); sc.Full {
		t.Error("水位已知后不应再自行走全量")
	}
}
