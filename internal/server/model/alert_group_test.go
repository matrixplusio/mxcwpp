package model

import (
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newGroupDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{
		Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// AutoMigrate 用不了：alerts 的 updated_at 带 MySQL 专有的 ON UPDATE 子句。
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT DEFAULT 'observe', would_action TEXT, action TEXT, action_result TEXT,
		attck_tactic TEXT, attck_technique TEXT, result_id TEXT UNIQUE NOT NULL,
		host_id TEXT, rule_id TEXT, policy_id TEXT, source TEXT DEFAULT '', severity TEXT,
		risk_score INTEGER DEFAULT 0, category TEXT, title TEXT, description TEXT,
		actual TEXT, expected TEXT, fix_suggestion TEXT, status TEXT DEFAULT 'active',
		first_seen_at DATETIME, last_seen_at DATETIME, hit_count INTEGER DEFAULT 1,
		last_notified_at DATETIME, notify_count INTEGER DEFAULT 0,
		resolved_at DATETIME, resolved_by TEXT, resolve_reason TEXT,
		verdict TEXT, verdict_basis TEXT, group_key TEXT, recurrence_of INTEGER, suppression_id INTEGER,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

// hit 模拟一次命中：并入时累加次数。
func hit(t *testing.T, db *gorm.DB, groupKey string) *Alert {
	t.Helper()
	created, err := UpsertGroupedAlert(db, groupKey, func() Alert {
		return Alert{HostID: "h1", RuleID: "cel-1", Severity: "high", Title: "t", Status: AlertStatusActive, HitCount: 1}
	}, func(existing *Alert) error {
		return db.Model(existing).Update("hit_count", gorm.Expr("hit_count + 1")).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func rowsOf(t *testing.T, db *gorm.DB) []Alert {
	t.Helper()
	var rows []Alert
	db.Order("id").Find(&rows)
	return rows
}

func TestFirstHitCreatesAlertWithGroupKey(t *testing.T) {
	db := newGroupDB(t)
	if hit(t, db, "cel-1-h1") == nil {
		t.Fatal("首次命中应新建告警")
	}
	rows := rowsOf(t, db)
	if len(rows) != 1 || rows[0].ResultID != "cel-1-h1" || rows[0].GroupKey != "cel-1-h1" || rows[0].RecurrenceOf != nil {
		t.Fatalf("首条告警身份不对: %+v", rows)
	}
}

func TestOpenAlertAbsorbsHits(t *testing.T) {
	for _, open := range []AlertStatus{AlertStatusActive, AlertStatusSuppressed} {
		db := newGroupDB(t)
		hit(t, db, "g")
		db.Model(&Alert{}).Where("1=1").Update("status", open)
		for i := 0; i < 2; i++ {
			if hit(t, db, "g") != nil {
				t.Fatalf("%s 的告警应吸收命中而不是新建", open)
			}
		}
		if rows := rowsOf(t, db); len(rows) != 1 || rows[0].HitCount != 3 {
			t.Fatalf("%s: 应只有一行且 hit=3，实际 %+v", open, rows)
		}
	}
}

// 关闭过的告警是定案记录：再命中生成复发告警，原告警一个字段都不动。
func TestClosedAlertIsNeverRewritten(t *testing.T) {
	for _, closed := range []AlertStatus{AlertStatusResolved, AlertStatusIgnored} {
		db := newGroupDB(t)
		hit(t, db, "g")
		db.Model(&Alert{}).Where("1=1").Updates(map[string]any{"status": closed, "verdict": "false_positive"})

		if hit(t, db, "g") == nil {
			t.Fatalf("%s 后再命中应新建复发告警", closed)
		}
		hit(t, db, "g") // 复发告警仍开着，这次并入它

		rows := rowsOf(t, db)
		if len(rows) != 2 {
			t.Fatalf("%s: 应为原告警 + 复发告警，实际 %d 行", closed, len(rows))
		}
		if rows[0].Status != closed || rows[0].HitCount != 1 || rows[0].Verdict != "false_positive" {
			t.Errorf("%s: 原告警被改写了: %+v", closed, rows[0])
		}
		if rows[1].Status != AlertStatusActive || rows[1].HitCount != 2 || rows[1].GroupKey != "g" ||
			rows[1].RecurrenceOf == nil || *rows[1].RecurrenceOf != rows[0].ID ||
			!strings.HasPrefix(rows[1].ResultID, "g#") {
			t.Errorf("%s: 复发告警不对: %+v", closed, rows[1])
		}
	}
}

// 还没回填 group_key 的存量告警，按 result_id 认作同一分组。
func TestLegacyRowWithoutGroupKeyIsFound(t *testing.T) {
	db := newGroupDB(t)
	db.Create(&Alert{ResultID: "cel-1-h1", HostID: "h1", RuleID: "cel-1", Severity: "high", Title: "t", Status: AlertStatusIgnored, HitCount: 1})

	if hit(t, db, "cel-1-h1") == nil {
		t.Fatal("存量的已忽略告警应触发复发")
	}
	rows := rowsOf(t, db)
	if len(rows) != 2 || rows[1].RecurrenceOf == nil || *rows[1].RecurrenceOf != rows[0].ID {
		t.Fatalf("应关联到存量告警: %+v", rows)
	}
}

// IOC 的分组键含指标值（可能是长 URL），加上后缀后不能撑破 result_id 列宽。
func TestLongGroupKeyFitsResultID(t *testing.T) {
	db := newGroupDB(t)
	long := "ioc-url-https://example.com/" + strings.Repeat("a", 150) + "-h1"
	hit(t, db, long)
	db.Model(&Alert{}).Where("1=1").Update("status", AlertStatusResolved)
	hit(t, db, long)

	for _, r := range rowsOf(t, db) {
		if len(r.ResultID) > maxResultIDLen {
			t.Errorf("result_id 长度 %d 超过列宽", len(r.ResultID))
		}
		if r.GroupKey != long {
			t.Errorf("分组键应保留原值以便查询")
		}
	}
	if fitResultID(long, "#1") == fitResultID(long, "#2") {
		t.Error("不同复发后缀必须得到不同 result_id")
	}
}

// 被抑制的命中单独成组，不能并进人在处置的告警。
func TestSuppressedHitsHaveTheirOwnGroup(t *testing.T) {
	db := newGroupDB(t)
	hit(t, db, "g")
	hit(t, db, SuppressedGroupKey("g"))
	if rows := rowsOf(t, db); len(rows) != 2 || rows[0].GroupKey == rows[1].GroupKey {
		t.Fatalf("抑制命中应另起一组: %+v", rows)
	}
}
