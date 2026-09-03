package intrusion

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newProfileDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// sqlite :memory: 每条连接是各自独立的库，限单连接让重载看到同一份数据。
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.HostLoginProfileState{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// learningBase 是学习期样本的起点: 30 天前的上午 9 点。
// 固定在 9 点，避开 0-5 点那条时间维规则。
func learningBase() time.Time {
	t := time.Now().Add(-30 * 24 * time.Hour)
	return time.Date(t.Year(), t.Month(), t.Day(), 9, 0, 0, 0, t.Location())
}

// warmUp 让一台主机走完学习期。样本按天分布——毕业判的是事件时间跨度，
// 十次登录挤在同一天不算走完 7 天学习期。
func warmUp(t *testing.T, d *AbnormalLoginDetector, hostID string, base time.Time) {
	t.Helper()
	for i := 0; i < DefaultLearningMinSamples; i++ {
		if _, hit := d.Ingest(context.Background(), SuccessfulLogin{
			HostID:    hostID,
			Username:  "ops",
			SourceIP:  "10.0.1.5",
			Country:   "CN",
			Timestamp: base.Add(time.Duration(i) * 24 * time.Hour),
		}); hit {
			t.Fatalf("学习期内不应产告警 (第 %d 次)", i)
		}
	}
}

// 画像落库后重载，已知的国家/用户/IP 段不再算「首次见到」。
func TestProfileRoundTripKeepsKnownDimensions(t *testing.T) {
	db := newProfileDB(t)
	base := learningBase()

	first := NewAbnormalLoginDetectorWithStore(db, nil)
	warmUp(t, first, "host-1", base)
	first.Checkpoint()

	second := NewAbnormalLoginDetectorWithStore(db, nil)
	second.LoadFromDB()

	// 同一个用户 / IP 段 / 国家，画像若丢了会命中三条异常。
	payload, hit := second.Ingest(context.Background(), SuccessfulLogin{
		HostID:    "host-1",
		Username:  "ops",
		SourceIP:  "10.0.1.9",
		Country:   "CN",
		Timestamp: base.Add(11 * 24 * time.Hour),
	})
	if hit {
		t.Fatalf("画像已恢复，已知维度不应告警: %s", payload)
	}

	st := second.Stats()
	if st.HostsGraduated != 1 {
		t.Fatalf("重载后应仍是已毕业主机, got %+v", st)
	}
}

// 学习期不因重启重新计时: 重载后遇到真正的新维度立刻告警。
func TestReloadedProfileStaysGraduated(t *testing.T) {
	db := newProfileDB(t)
	base := learningBase()

	first := NewAbnormalLoginDetectorWithStore(db, nil)
	warmUp(t, first, "host-1", base)
	first.Checkpoint()

	second := NewAbnormalLoginDetectorWithStore(db, nil)
	second.LoadFromDB()

	_, hit := second.Ingest(context.Background(), SuccessfulLogin{
		HostID:    "host-1",
		Username:  "root",
		SourceIP:  "203.0.113.7",
		Country:   "RU",
		Timestamp: base.Add(12 * 24 * time.Hour),
	})
	if !hit {
		t.Fatal("重载后的已毕业主机遇到新国家/新用户/新 IP 段应告警")
	}
}

// 没配持久化后端时 Load/Checkpoint 是空操作，不影响纯内存检测。
func TestPersistenceNoopWithoutStore(t *testing.T) {
	d := NewAbnormalLoginDetector()
	d.LoadFromDB()
	d.Checkpoint()
	d.StartCheckpoint(context.Background(), time.Millisecond)

	if _, hit := d.Ingest(context.Background(), SuccessfulLogin{
		HostID: "host-1", Username: "ops", SourceIP: "10.0.1.5", Timestamp: time.Now(),
	}); hit {
		t.Fatal("学习期内不应告警")
	}
}

// 超过 TTL 的用户/IP 段条目被丢弃，避免画像行无限增长。
func TestPruneDropsExpiredEntries(t *testing.T) {
	d := NewAbnormalLoginDetector()
	base := time.Now().Add(-200 * 24 * time.Hour)

	d.Ingest(context.Background(), SuccessfulLogin{
		HostID: "host-1", Username: "legacy", SourceIP: "10.0.1.5", Timestamp: base,
	})
	// 100 天后的一次登录: legacy / 10.0.1.0/24 都已超过 90 天 TTL。
	d.Ingest(context.Background(), SuccessfulLogin{
		HostID: "host-1", Username: "ops", SourceIP: "10.0.2.5",
		Timestamp: base.Add(100 * 24 * time.Hour),
	})

	d.mu.Lock()
	p := d.profiles["host-1"]
	_, hasLegacyUser := p.UsersSeen["legacy"]
	_, hasLegacyNet := p.IPv4Net24["10.0.1.0/24"]
	d.mu.Unlock()

	if hasLegacyUser || hasLegacyNet {
		t.Fatalf("超过 %v 的条目应被清理", profileEntryTTL)
	}
}

// 90 天内条目过多时按 last-seen 保留最新的 profileEntryCap 条。
func TestPruneEnforcesEntryCap(t *testing.T) {
	d := NewAbnormalLoginDetector()
	base := time.Now().Add(-24 * time.Hour)

	total := profileEntryCap + 100
	for i := 0; i < total; i++ {
		d.Ingest(context.Background(), SuccessfulLogin{
			HostID:   "host-1",
			SourceIP: fmt.Sprintf("10.%d.%d.5", i/256, i%256),
			// 每条差 1 秒，最早的那批应被挤掉。
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	d.mu.Lock()
	p := d.profiles["host-1"]
	size := len(p.IPv4Net24)
	_, hasOldest := p.IPv4Net24["10.0.0.0/24"]
	_, hasNewest := p.IPv4Net24[ipToNet24(fmt.Sprintf("10.%d.%d.5", (total-1)/256, (total-1)%256))]
	d.mu.Unlock()

	if size > profileEntryCap {
		t.Fatalf("IP 段条目数 %d 超过上限 %d", size, profileEntryCap)
	}
	if hasOldest {
		t.Fatal("最旧的 IP 段应被挤掉")
	}
	if !hasNewest {
		t.Fatal("最新的 IP 段应保留")
	}
}

// 重复 Checkpoint 走 upsert，不会给同一台主机留多行。
func TestCheckpointUpsertsSingleRow(t *testing.T) {
	db := newProfileDB(t)
	base := learningBase()

	d := NewAbnormalLoginDetectorWithStore(db, nil)
	warmUp(t, d, "host-1", base)
	d.Checkpoint()

	d.Ingest(context.Background(), SuccessfulLogin{
		HostID: "host-1", Username: "ops", SourceIP: "10.0.1.5", Country: "CN",
		Timestamp: base.Add(12 * 24 * time.Hour),
	})
	d.Checkpoint()

	var rows []model.HostLoginProfileState
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("同一台主机应只有一行, got %d", len(rows))
	}
	if rows[0].Samples != DefaultLearningMinSamples+1 {
		t.Fatalf("样本数应随更新落库, got %d", rows[0].Samples)
	}
}

// 学习期指标必须能被抓到: 学习期静默不告警，没有指标就分不清
// 「一切正常」和「检测根本没生效」。
func TestLearningMetricsExposed(t *testing.T) {
	d := NewAbnormalLoginDetector()
	base := learningBase()
	warmUp(t, d, "graduated-host", base)
	// 另一台主机刚开始学习，且在学习期内被抑制掉一条告警。
	d.Ingest(context.Background(), SuccessfulLogin{
		HostID: "learning-host", Username: "ops", SourceIP: "10.0.9.5", Country: "CN",
		Timestamp: base.Add(20 * 24 * time.Hour),
	})

	reg := prometheus.NewRegistry()
	if err := d.RegisterMetrics(reg); err != nil {
		t.Fatalf("注册指标失败: %v", err)
	}

	for metric, want := range map[string]float64{
		"mxcwpp_engine_abnormal_login_hosts_graduated": 1,
		"mxcwpp_engine_abnormal_login_hosts_learning":  1,
	} {
		if got := gaugeValue(t, reg, metric); got != want {
			t.Errorf("%s = %v, want %v", metric, got, want)
		}
	}
}

// gaugeValue 从注册表里读一个无标签指标的当前值。
func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("指标 %s 未暴露", name)
	return 0
}
