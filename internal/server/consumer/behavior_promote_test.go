package consumer

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupBehaviorAlertDB 建 alerts 表。updated_at 带 MySQL 专有的 ON UPDATE，SQLite 建不了，手写表结构。
func setupBehaviorAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id varchar(64) NOT NULL DEFAULT 't-default', id integer PRIMARY KEY AUTOINCREMENT,
		mode varchar(20) NOT NULL DEFAULT 'observe', would_action text, action text, action_result text,
		attck_tactic varchar(64), attck_technique varchar(64), result_id varchar(128) NOT NULL UNIQUE,
		host_id varchar(64) NOT NULL, rule_id varchar(64) NOT NULL, policy_id varchar(64),
		source varchar(20) NOT NULL DEFAULT '', severity varchar(20) NOT NULL, risk_score integer NOT NULL DEFAULT 0,
		category varchar(50), title varchar(255) NOT NULL, description text, actual text, expected text,
		fix_suggestion text, status varchar(20) NOT NULL DEFAULT 'active',
		first_seen_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
		hit_count integer DEFAULT 1, last_notified_at timestamp, notify_count integer DEFAULT 0,
		resolved_at timestamp, resolved_by varchar(100), resolve_reason text, verdict varchar(32), verdict_basis varchar(16),
		group_key varchar(191), recurrence_of integer, suppression_id integer,
		created_at timestamp DEFAULT CURRENT_TIMESTAMP, updated_at timestamp DEFAULT CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatalf("create alerts: %v", err)
	}
	return db
}

func TestPromoteBehaviorAlertGroupsAndRecurs(t *testing.T) {
	db := setupBehaviorAlertDB(t)
	dev := behaviorDeviation{HostID: "h1", Hostname: "web-01", Metric: "net_unique_ip",
		Value: 180, Mean: 12, Stddev: 4, ZScore: 42, RiskScore: 78}
	now := time.Now()

	first, err := promoteBehaviorAlert(db, dev, now)
	if err != nil || first == nil {
		t.Fatalf("首次偏离应新建告警: created=%v err=%v", first, err)
	}
	if first.Source != model.AlertSourceBehavior || first.RuleID != "bde-net_unique_ip" || first.Severity != "high" {
		t.Errorf("告警内容不对: source=%s rule=%s severity=%s", first.Source, first.RuleID, first.Severity)
	}

	// 同一主机同一指标再次偏离：并入同一条，不新建。
	again, err := promoteBehaviorAlert(db, dev, now.Add(time.Minute))
	if err != nil || again != nil {
		t.Fatalf("开着的告警应吸收命中: created=%v err=%v", again, err)
	}
	var merged model.Alert
	db.First(&merged, first.ID)
	if merged.HitCount != 2 {
		t.Errorf("hit_count=%d 期望 2", merged.HitCount)
	}

	// 研判关闭后再偏离：生成复发告警，指向上一条，原告警不被改写。
	db.Model(&model.Alert{}).Where("id = ?", first.ID).Updates(map[string]any{
		"status": model.AlertStatusResolved, "verdict": model.VerdictFalsePositive})
	recur, err := promoteBehaviorAlert(db, dev, now.Add(time.Hour))
	if err != nil || recur == nil {
		t.Fatalf("关闭后再偏离应生成复发告警: created=%v err=%v", recur, err)
	}
	if recur.RecurrenceOf == nil || *recur.RecurrenceOf != first.ID {
		t.Errorf("复发告警应指向 #%d, 得 %v", first.ID, recur.RecurrenceOf)
	}
	var closed model.Alert
	db.First(&closed, first.ID)
	if closed.Status != model.AlertStatusResolved || closed.HitCount != 2 {
		t.Errorf("已关闭的告警被改写: status=%s hit=%d", closed.Status, closed.HitCount)
	}

	// 其它主机同一指标是另一组。
	other := dev
	other.HostID = "h2"
	if created, err := promoteBehaviorAlert(db, other, now); err != nil || created == nil {
		t.Errorf("另一台主机应单独成组: created=%v err=%v", created, err)
	}
}
