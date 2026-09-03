package engine

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	// 手写建表：model.Alert 含 MySQL 专属列定义，sqlite 无法 AutoMigrate。
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT DEFAULT 'observe',
		would_action TEXT, action TEXT, action_result TEXT,
		attck_tactic TEXT, attck_technique TEXT,
		result_id TEXT NOT NULL UNIQUE,
		host_id TEXT NOT NULL, rule_id TEXT NOT NULL, policy_id TEXT,
		source TEXT DEFAULT '', severity TEXT, risk_score INTEGER DEFAULT 0,
		category TEXT, title TEXT, description TEXT,
		actual TEXT, expected TEXT, fix_suggestion TEXT,
		status TEXT DEFAULT 'active',
		first_seen_at DATETIME, last_seen_at DATETIME,
		hit_count INTEGER DEFAULT 1,
		last_notified_at DATETIME, notify_count INTEGER DEFAULT 0,
		resolved_at DATETIME, resolved_by TEXT, resolve_reason TEXT,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func countAlerts(t *testing.T, db *gorm.DB) int {
	t.Helper()
	var n int
	if err := db.Raw(`SELECT COUNT(*) FROM alerts`).Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func sampleStageAlert() Alert {
	return Alert{
		RuleID:      "PRIV_SETUID_ROOT",
		Severity:    "high",
		ATTCKTactic: "TA0004",
		Payload:     json.RawMessage(`{"exe":"/tmp/x","uid":"0"}`),
	}
}

// TestStageAlertWriter_PersistsToAlertsTable 不自带落库的 Stage 告警必须真的进 alerts 表。
//
// 此前 Privilege / RASP / AntiRootkit 只把告警推到 mxcwpp.engine.alert，而该 topic
// 没有任何消费者——检测在跑、告警在发、界面上永远看不到。
func TestStageAlertWriter_PersistsToAlertsTable(t *testing.T) {
	db := newAlertDB(t)
	w := NewStageAlertWriter(db, zap.NewNop())

	ev := PipelineEvent{HostID: "host-a"}
	if err := w.Persist("privilege", ev, sampleStageAlert()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if got := countAlerts(t, db); got != 1 {
		t.Fatalf("应落库 1 条，实际 %d", got)
	}

	var resultID, ruleID string
	db.Raw(`SELECT result_id, rule_id FROM alerts`).Row().Scan(&resultID, &ruleID)
	if resultID != "engine-PRIV_SETUID_ROOT-host-a" {
		t.Errorf("result_id = %q，未按稳定身份生成", resultID)
	}
	if ruleID != "PRIV_SETUID_ROOT" {
		t.Errorf("rule_id = %q", ruleID)
	}
}

// TestStageAlertWriter_RepeatHitAccumulates 同一主机同一规则重复命中应累加计数，
// 而不是刷出无数行——result_id 刻意不含时间戳。
func TestStageAlertWriter_RepeatHitAccumulates(t *testing.T) {
	db := newAlertDB(t)
	w := NewStageAlertWriter(db, zap.NewNop())
	ev := PipelineEvent{HostID: "host-a"}

	for i := 0; i < 3; i++ {
		if err := w.Persist("privilege", ev, sampleStageAlert()); err != nil {
			t.Fatalf("第 %d 次 Persist: %v", i+1, err)
		}
	}
	if got := countAlerts(t, db); got != 1 {
		t.Fatalf("重复命中应合并为 1 行，实际 %d 行", got)
	}
	var hits int
	db.Raw(`SELECT hit_count FROM alerts`).Scan(&hits)
	if hits != 3 {
		t.Errorf("hit_count = %d, want 3", hits)
	}
}

// TestStageAlertWriter_ReopensResolved 已处置的告警重新命中要回到活跃态，
// 否则复发会被旧的处置状态盖住而无人知晓。
func TestStageAlertWriter_ReopensResolved(t *testing.T) {
	db := newAlertDB(t)
	w := NewStageAlertWriter(db, zap.NewNop())
	ev := PipelineEvent{HostID: "host-a"}

	if err := w.Persist("privilege", ev, sampleStageAlert()); err != nil {
		t.Fatal(err)
	}
	db.Exec(`UPDATE alerts SET status = 'resolved'`)
	if err := w.Persist("privilege", ev, sampleStageAlert()); err != nil {
		t.Fatal(err)
	}
	var status string
	db.Raw(`SELECT status FROM alerts`).Scan(&status)
	if status != "active" {
		t.Errorf("复发后状态 = %q, want active", status)
	}
}

// TestStageAlertWriter_RejectsMissingIdentity 缺少去重维度的告警必须被拒，
// 否则会不断堆积无法合并的重复行。
func TestStageAlertWriter_RejectsMissingIdentity(t *testing.T) {
	db := newAlertDB(t)
	w := NewStageAlertWriter(db, zap.NewNop())

	if err := w.Persist("privilege", PipelineEvent{}, sampleStageAlert()); err == nil {
		t.Error("缺 host_id 应报错")
	}
	noRule := sampleStageAlert()
	noRule.RuleID = "  "
	if err := w.Persist("privilege", PipelineEvent{HostID: "h"}, noRule); err == nil {
		t.Error("缺 rule_id 应报错")
	}
	if got := countAlerts(t, db); got != 0 {
		t.Errorf("不合法告警不应落库，实际 %d 行", got)
	}
}

// fakeSelfPersisting 模拟自带落库的 Stage。
type fakeSelfPersisting struct{ selfPersist bool }

func (f *fakeSelfPersisting) Name() string { return "fake" }
func (f *fakeSelfPersisting) Process(context.Context, PipelineEvent) ([]Alert, error) {
	return nil, nil
}
func (f *fakeSelfPersisting) PersistsOwnAlerts() bool { return f.selfPersist }

// plainStage 不实现 selfPersistingStage。
type plainStage struct{}

func (plainStage) Name() string                                            { return "plain" }
func (plainStage) Process(context.Context, PipelineEvent) ([]Alert, error) { return nil, nil }

// TestStageSelfPersists 自带落库的 Stage 必须被识别出来，
// 否则 CEL / Sequence / IOC 的命中会被写两遍，界面上出现两条同源告警。
func TestStageSelfPersists(t *testing.T) {
	if !stageSelfPersists(&fakeSelfPersisting{selfPersist: true}) {
		t.Error("自带落库的 Stage 未被识别")
	}
	if stageSelfPersists(&fakeSelfPersisting{selfPersist: false}) {
		t.Error("未挂 AlertGenerator 时不应算作自带落库")
	}
	if stageSelfPersists(plainStage{}) {
		t.Error("未实现该接口的 Stage 不应算作自带落库")
	}
}
