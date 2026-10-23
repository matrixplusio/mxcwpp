package scheduler

import (
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newTelemetryGapDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	for _, ddl := range []string{
		`CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT DEFAULT 't-default',
			host_id TEXT, hostname TEXT, ipv4 TEXT, status TEXT, last_heartbeat DATETIME,
			last_data_at DATETIME, agent_start_time DATETIME)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	// alerts 列多且带 MySQL 专有默认值，按模型字段生成一份宽松的 sqlite 表。
	st, err := schema.Parse(&model.Alert{}, &sync.Map{}, db.NamingStrategy)
	if err != nil {
		t.Fatal(err)
	}
	cols := []string{"id INTEGER PRIMARY KEY AUTOINCREMENT"}
	for _, f := range st.Fields {
		if f.DBName != "" && f.DBName != "id" {
			typ := ""
			if strings.Contains(strings.ToLower(string(f.DataType)), "time") || f.DataType == schema.Time {
				typ = " DATETIME" // 让驱动按时间解析，否则 LocalTime 扫描失败
			}
			cols = append(cols, f.DBName+typ)
		}
	}
	if err := db.Exec("CREATE TABLE alerts (" + strings.Join(cols, ", ") + ")").Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func seedGapHost(t *testing.T, db *gorm.DB, id, status string, hb, data, start *time.Time) {
	t.Helper()
	if err := db.Exec(`INSERT INTO hosts (host_id, hostname, ipv4, status, last_heartbeat, last_data_at, agent_start_time)
		VALUES (?, ?, '[]', ?, ?, ?, ?)`, id, id, status, hb, data, start).Error; err != nil {
		t.Fatal(err)
	}
}

func activeGapAlerts(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()
	var rows []model.Alert
	db.Where("rule_id = ? AND status = ?", telemetryGapRuleID, model.AlertStatusActive).Find(&rows)
	out := map[string]bool{}
	for _, r := range rows {
		out[r.HostID] = true
	}
	return out
}

// TestTelemetryGap_OnlyOnlineHostsWithStaleData 只有「在线、曾经送过数据、且已超阈值」的主机才告警。
// 空 last_data_at 不判，否则上线瞬间全网告警；刚启动的 agent 不判，插件还在拉起。
func TestTelemetryGap_OnlyOnlineHostsWithStaleData(t *testing.T) {
	db := newTelemetryGapDB(t)
	now := time.Now()
	fresh := now.Add(-time.Minute)
	stale := now.Add(-7 * time.Hour)
	oldStart := now.Add(-48 * time.Hour)
	newStart := now.Add(-10 * time.Minute)

	seedGapHost(t, db, "gap", "online", &fresh, &stale, &oldStart)
	seedGapHost(t, db, "ok", "online", &fresh, &fresh, &oldStart)
	seedGapHost(t, db, "never", "online", &fresh, nil, &oldStart)
	seedGapHost(t, db, "offline", "offline", &stale, &stale, &oldStart)
	seedGapHost(t, db, "just-started", "online", &fresh, &stale, &newStart)

	checkTelemetryGap(db, zap.NewNop(), now)

	got := activeGapAlerts(t, db)
	if !got["gap"] || len(got) != 1 {
		t.Fatalf("只应对 gap 告警，实际 %v", got)
	}

	// 再跑一轮不重复建
	checkTelemetryGap(db, zap.NewNop(), now)
	var n int64
	db.Model(&model.Alert{}).Where("rule_id = ?", telemetryGapRuleID).Count(&n)
	if n != 1 {
		t.Errorf("重复检测不应新建告警，实际 %d 条", n)
	}
}

// TestTelemetryGap_ResolvesWhenDataResumesAndReopens 数据恢复即自动恢复；再次中断复用同一行并重新通知。
func TestTelemetryGap_ResolvesWhenDataResumesAndReopens(t *testing.T) {
	db := newTelemetryGapDB(t)
	now := time.Now()
	fresh := now.Add(-time.Minute)
	stale := now.Add(-7 * time.Hour)
	oldStart := now.Add(-48 * time.Hour)
	seedGapHost(t, db, "h", "online", &fresh, &stale, &oldStart)

	checkTelemetryGap(db, zap.NewNop(), now)
	db.Model(&model.Alert{}).Where("host_id = ?", "h").Update("last_notified_at", now)

	db.Exec(`UPDATE hosts SET last_data_at = ? WHERE host_id = 'h'`, fresh)
	checkTelemetryGap(db, zap.NewNop(), now)
	var a model.Alert
	db.Where("host_id = ?", "h").First(&a)
	if a.Status != model.AlertStatusResolved || a.ResolveReason != "插件数据已恢复" {
		t.Fatalf("数据恢复后应自动恢复，实际 status=%s reason=%q", a.Status, a.ResolveReason)
	}

	db.Exec(`UPDATE hosts SET last_data_at = ? WHERE host_id = 'h'`, stale)
	checkTelemetryGap(db, zap.NewNop(), now)
	var re model.Alert // 用新变量：GORM 扫描 NULL 不会清空已有结构体里的指针
	db.Where("host_id = ?", "h").First(&re)
	if re.Status != model.AlertStatusActive || re.LastNotifiedAt != nil {
		t.Fatalf("再次中断应重新激活并待通知，实际 status=%s notified=%v", re.Status, re.LastNotifiedAt)
	}
}

// TestTelemetryGap_ResolvesWhenHostGoesOffline 离线由心跳超时告警接管，不两条并存。
func TestTelemetryGap_ResolvesWhenHostGoesOffline(t *testing.T) {
	db := newTelemetryGapDB(t)
	now := time.Now()
	fresh := now.Add(-time.Minute)
	stale := now.Add(-7 * time.Hour)
	oldStart := now.Add(-48 * time.Hour)
	seedGapHost(t, db, "h", "online", &fresh, &stale, &oldStart)
	checkTelemetryGap(db, zap.NewNop(), now)

	db.Exec(`UPDATE hosts SET status = 'offline' WHERE host_id = 'h'`)
	checkTelemetryGap(db, zap.NewNop(), now)
	if got := activeGapAlerts(t, db); len(got) != 0 {
		t.Fatalf("主机离线后采集中断告警应恢复，实际仍活跃 %v", got)
	}
}
