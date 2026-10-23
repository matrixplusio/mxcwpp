package baseline

import (
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestNextTuningMult 校验反馈闭环调参决策（纯逻辑）。
func TestNextTuningMult(t *testing.T) {
	cases := []struct {
		name        string
		current     float64
		ignoredRate float64
		samples     int
		want        float64
	}{
		{"样本不足不动", 1.0, 0.95, 10, 1.0},
		{"高误报抬高", 1.0, 0.9, 100, 1.5},
		{"高误报封顶", 3.0, 0.9, 100, maxTuningMult}, // 3*1.5=4.5 → 封顶 4.0
		{"低误报缓降", 2.0, 0.1, 100, 1.6},
		{"低误报下限1", 1.0, 0.1, 100, 1.0},
		{"中间保持", 1.5, 0.5, 100, 1.5},
	}
	for _, c := range cases {
		if got := nextTuningMult(c.current, c.ignoredRate, c.samples); got != c.want {
			t.Errorf("%s: nextTuningMult(%v,%v,%d)=%v 期望 %v", c.name, c.current, c.ignoredRate, c.samples, got, c.want)
		}
	}
}

// TestReloadTuning 校验从主告警表里已研判的行为告警算噪声率并落库 + 刷新内存快照，敏感指标豁免。
//
// 输入必须是人真正处置过的东西：behavior_alerts 没有任何代码会改它的 status，
// 以它为输入时调优环永远拿不到样本。
func TestReloadTuning(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&model.BDEMetricTuning{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	// alerts 的 updated_at 带 MySQL 专有的 ON UPDATE，SQLite 建不了，手写表结构。
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

	recent := model.ToLocalTime(time.Now().Add(-time.Hour))
	stale := model.ToLocalTime(time.Now().Add(-tuningWindow - 24*time.Hour))
	n := 0
	seed := func(source, ruleID string, status model.AlertStatus, verdict string, resolvedAt *model.LocalTime, count int) {
		for range count {
			n++
			a := model.Alert{
				ResultID: fmt.Sprintf("r%d", n), HostID: "h", RuleID: ruleID, Source: source,
				Severity: "medium", Title: "t", Status: status, Verdict: verdict, VerdictBasis: model.VerdictBasisIndividual, ResolvedAt: resolvedAt,
			}
			if err := db.Create(&a).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	// net_connect_count：80 误报 + 10 良性 + 10 真实 → 噪声率 0.9(高) → 抬到 1.5。
	seed(model.AlertSourceBehavior, "bde-net_connect_count", model.AlertStatusResolved, model.VerdictFalsePositive, &recent, 80)
	seed(model.AlertSourceBehavior, "bde-net_connect_count", model.AlertStatusResolved, model.VerdictBenignTruePositive, &recent, 10)
	seed(model.AlertSourceBehavior, "bde-net_connect_count", model.AlertStatusResolved, model.VerdictTruePositive, &recent, 10)
	// 不该计入的：还没处置的、窗口外的、其他来源同名规则的。
	seed(model.AlertSourceBehavior, "bde-net_connect_count", model.AlertStatusActive, "", nil, 50)
	seed(model.AlertSourceBehavior, "bde-net_connect_count", model.AlertStatusResolved, model.VerdictTruePositive, &stale, 50)
	seed(model.AlertSourceDetection, "bde-net_connect_count", model.AlertStatusResolved, model.VerdictTruePositive, &recent, 50)
	// file_sensitive_hits：全是误报(敏感指标) → 豁免，保持 1.0。
	seed(model.AlertSourceBehavior, "bde-file_sensitive_hits", model.AlertStatusResolved, model.VerdictFalsePositive, &recent, 100)

	e := &Engine{db: db, logger: zap.NewNop()}
	e.reloadTuning()

	// 内存快照：net_connect_count 抬到 1.5，file_sensitive_hits 豁免=1.0。
	nci := metricIndexByName("net_connect_count")
	if got := e.tuningMult(nci); got != 1.5 {
		t.Errorf("net_connect_count 动态倍率=%v 期望 1.5", got)
	}
	if got := e.tuningMult(MetricFileSensitiveHits); got != 1.0 {
		t.Errorf("敏感指标应豁免=1.0, 得 %v", got)
	}

	// 落库校验。
	var row model.BDEMetricTuning
	if err := db.Where("metric = ?", "net_connect_count").First(&row).Error; err != nil {
		t.Fatalf("tuning 未落库: %v", err)
	}
	if row.ThresholdMult != 1.5 || row.Samples != 100 {
		t.Errorf("落库值 mult=%v samples=%d 期望 1.5/100", row.ThresholdMult, row.Samples)
	}
}
