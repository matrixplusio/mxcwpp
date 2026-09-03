package casework

import (
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newTestService(t *testing.T) (*Service, *gorm.DB) {
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
	if err := db.Exec(`CREATE TABLE incidents (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		incident_id TEXT NOT NULL UNIQUE, host_id TEXT, hostname TEXT,
		status TEXT DEFAULT 'active', severity TEXT, risk_score REAL,
		tactics TEXT, tactic_count INTEGER, alert_ids TEXT, alert_count INTEGER,
		behavior_alert_count INTEGER, storyline_ids TEXT, title TEXT, summary TEXT,
		owner TEXT, assigned_at DATETIME, assigned_by TEXT,
		acked_at DATETIME, acked_by TEXT,
		ack_due_at DATETIME, resolve_due_at DATETIME,
		verdict TEXT, verdict_reason TEXT,
		escalated INTEGER DEFAULT 0, escalated_at DATETIME, escalated_to TEXT,
		close_reason TEXT,
		first_seen_at DATETIME, last_seen_at DATETIME,
		resolved_at DATETIME, resolved_by TEXT,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE incident_events (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		incident_id TEXT NOT NULL, type TEXT NOT NULL, actor TEXT NOT NULL,
		body TEXT, ref TEXT, created_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
	return NewService(db, zap.NewNop()), db
}

func seedIncident(t *testing.T, db *gorm.DB, id, severity string) {
	t.Helper()
	if err := db.Exec(
		`INSERT INTO incidents (incident_id, host_id, severity, status) VALUES (?, 'h-1', ?, 'active')`,
		id, severity).Error; err != nil {
		t.Fatal(err)
	}
}

func loadIncident(t *testing.T, db *gorm.DB, id string) model.Incident {
	t.Helper()
	var inc model.Incident
	if err := db.Where("incident_id = ?", id).First(&inc).Error; err != nil {
		t.Fatal(err)
	}
	return inc
}

// TestResolve_RequiresVerdict 关闭事件必须给出研判结论。
//
// 原实现只翻状态，关闭不需要任何理由，resolved_by 实际只会是 "auto"。
// 于是无法回答"这条到底是不是真威胁"——而这是检测质量的唯一可信来源：
// 拿 resolved 数量当 precision，会把"没人看所以批量关掉"算成检测准确。
func TestResolve_RequiresVerdict(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "high")

	for _, v := range []string{"", "done", "closed", "TRUE"} {
		if err := s.Resolve("inc-1", v, "查过了", "alice"); !errors.Is(err, ErrVerdictRequired) {
			t.Errorf("verdict=%q 应被拒绝，实际 %v", v, err)
		}
	}
	if got := loadIncident(t, db, "inc-1").Status; got != model.IncidentStatusActive {
		t.Errorf("被拒的关闭不应改变状态，实际 %q", got)
	}
}

// TestResolve_RequiresReason 关闭必须写明原因，否则复盘无从下手。
func TestResolve_RequiresReason(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "high")

	err := s.Resolve("inc-1", model.VerdictFalsePositive, "   ", "alice")
	if !errors.Is(err, ErrCloseReasonRequired) {
		t.Errorf("空原因应被拒绝，实际 %v", err)
	}
}

// TestResolve_RecordsVerdictAndTimeline 合法关闭要落结论、原因、操作人与时间线。
func TestResolve_RecordsVerdictAndTimeline(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "high")

	if err := s.Resolve("inc-1", model.VerdictBenignTruePositive, "运维批量变更所致", "alice"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	inc := loadIncident(t, db, "inc-1")
	if inc.Status != model.IncidentStatusResolved {
		t.Errorf("status = %q", inc.Status)
	}
	if inc.Verdict != model.VerdictBenignTruePositive {
		t.Errorf("verdict = %q", inc.Verdict)
	}
	if inc.CloseReason == "" {
		t.Error("关闭原因未记录")
	}
	if inc.ResolvedBy != "alice" {
		t.Errorf("resolved_by = %q，应记录真实操作人而非 auto", inc.ResolvedBy)
	}
	events, err := s.Timeline("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != model.IncidentEventResolved {
		t.Fatalf("时间线应有 1 条关闭记录，实际 %d 条", len(events))
	}
}

// TestAck_SetsOwnerWhenUnassigned 无人负责的事件被谁认领，谁就成为负责人，
// 避免出现"已认领但仍无人负责"。
func TestAck_SetsOwnerWhenUnassigned(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "critical")

	if err := s.Ack("inc-1", "bob"); err != nil {
		t.Fatal(err)
	}
	inc := loadIncident(t, db, "inc-1")
	if inc.Owner != "bob" {
		t.Errorf("owner = %q, want bob", inc.Owner)
	}
	if inc.AckedAt == nil {
		t.Error("认领时间未记录，MTTA 无从计算")
	}
	if inc.Status != model.IncidentStatusInvestigating {
		t.Errorf("认领后状态 = %q", inc.Status)
	}
}

// TestAck_DoesNotRefreshOnRepeat 重复认领不刷新时间——
// MTTA 该记第一个真正开始看的人，而不是最后一个点开页面的人。
func TestAck_DoesNotRefreshOnRepeat(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "high")

	if err := s.Ack("inc-1", "bob"); err != nil {
		t.Fatal(err)
	}
	first := loadIncident(t, db, "inc-1").AckedAt

	s.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := s.Ack("inc-1", "carol"); err != nil {
		t.Fatal(err)
	}
	after := loadIncident(t, db, "inc-1")
	if !after.AckedAt.Time().Equal(first.Time()) {
		t.Error("重复认领刷新了 MTTA 终点")
	}
	if after.AckedBy != "bob" {
		t.Errorf("acked_by = %q，应保留首个认领人", after.AckedBy)
	}
}

// TestEscalate_RequiresTargetAndReason 升级必须写明对象与原因，
// 否则"已升级"三个字事后无从追溯。
func TestEscalate_RequiresTargetAndReason(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "critical")

	if err := s.Escalate("inc-1", "", "原因", "alice"); err == nil {
		t.Error("缺升级对象应报错")
	}
	if err := s.Escalate("inc-1", "安全负责人", "  ", "alice"); err == nil {
		t.Error("缺升级原因应报错")
	}
	if err := s.Escalate("inc-1", "安全负责人", "疑似横向移动", "alice"); err != nil {
		t.Fatalf("合法升级失败: %v", err)
	}
	inc := loadIncident(t, db, "inc-1")
	if !inc.Escalated || inc.EscalatedTo != "安全负责人" {
		t.Errorf("升级未落库: escalated=%v to=%q", inc.Escalated, inc.EscalatedTo)
	}
}

// TestMutate_RejectsOperationsOnResolved 已关闭的事件不接受后续操作，
// 否则会出现"关闭后又被指派"这类无法解释的时间线。
func TestMutate_RejectsOperationsOnResolved(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "low")
	if err := s.Resolve("inc-1", model.VerdictTruePositive, "已处置", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Assign("inc-1", "bob", "alice"); !errors.Is(err, ErrAlreadyResolved) {
		t.Errorf("已关闭事件不应可指派，实际 %v", err)
	}
}

// TestTimeline_IsOrderedNarrative 时间线按时间正序，复盘要能顺着读下来。
func TestTimeline_IsOrderedNarrative(t *testing.T) {
	s, db := newTestService(t)
	seedIncident(t, db, "inc-1", "high")

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Assign("inc-1", "bob", "alice"))
	must(s.Ack("inc-1", "bob"))
	must(s.Comment("inc-1", "bob", "已确认进程来源", "storyline-9"))
	must(s.Escalate("inc-1", "安全负责人", "疑似横向移动", "bob"))
	must(s.Resolve("inc-1", model.VerdictTruePositive, "已隔离主机", "bob"))

	events, err := s.Timeline("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		model.IncidentEventAssigned, model.IncidentEventAcked,
		model.IncidentEventEvidence, model.IncidentEventEscalated,
		model.IncidentEventResolved,
	}
	if len(events) != len(want) {
		t.Fatalf("时间线 %d 条，want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].Type != w {
			t.Errorf("第 %d 条 = %q, want %q", i+1, events[i].Type, w)
		}
	}
	// 带 ref 的备注归为证据，供 chain-of-custody 追溯。
	if events[2].Ref != "storyline-9" {
		t.Errorf("证据引用未保留: %q", events[2].Ref)
	}
}

// TestSLADeadlines_ScaleWithSeverity 时限按严重级别区分。
// 一刀切要么低危把人拖垮，要么高危被淹没。
func TestSLADeadlines_ScaleWithSeverity(t *testing.T) {
	base := time.Unix(1700000000, 0)
	critAck, critResolve := SLADeadlines("critical", base)
	lowAck, lowResolve := SLADeadlines("low", base)

	if !critAck.Before(lowAck) {
		t.Error("critical 的认领时限应短于 low")
	}
	if !critResolve.Before(lowResolve) {
		t.Error("critical 的解决时限应短于 low")
	}
	// 未知级别按最宽处理：不因级别拼写错误就把人叫醒。
	unkAck, _ := SLADeadlines("bogus", base)
	if !unkAck.Equal(lowAck) {
		t.Error("未知级别应退到最宽时限")
	}
}
