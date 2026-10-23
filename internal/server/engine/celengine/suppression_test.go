package celengine

import (
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func suppressionRule(id uint, exe string, expires time.Time, enabled bool) model.AlertWhitelist {
	at := model.ToLocalTime(expires)
	return model.AlertWhitelist{ID: id, RuleID: "cel-46", HostID: "h1", Exe: exe, ExpiresAt: &at, Enabled: enabled}
}

func generateOnce(g *AlertGenerator, exe string) {
	rule := model.DetectionRule{Name: "r", Severity: "high", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh}
	rule.ID = 46
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": exe})
}

func alertsOf(t *testing.T, db *gorm.DB) []model.Alert {
	t.Helper()
	var rows []model.Alert
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// 命中生效的抑制规则：照常记录为 suppressed 并标注是哪条规则压下的，不产生 active 告警。
func TestSuppressedHitIsRecordedNotDropped(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	wl := []model.AlertWhitelist{suppressionRule(7, "backup.sh", time.Now().Add(time.Hour), true)}
	g.dbWhitelist.Store(&wl)

	generateOnce(g, "/opt/bin/backup.sh")

	rows := alertsOf(t, db)
	if len(rows) != 1 {
		t.Fatalf("被抑制的命中应留下一条记录，实际 %d", len(rows))
	}
	if rows[0].Status != model.AlertStatusSuppressed || rows[0].SuppressionID == nil || *rows[0].SuppressionID != 7 {
		t.Fatalf("应记为 suppressed 并指向抑制规则 7: %+v", rows[0])
	}
}

// 过期或停用的抑制规则不再生效。
func TestExpiredOrDisabledSuppressionDoesNotApply(t *testing.T) {
	for name, wl := range map[string]model.AlertWhitelist{
		"expired":  suppressionRule(7, "backup.sh", time.Now().Add(-time.Minute), true),
		"disabled": suppressionRule(7, "backup.sh", time.Now().Add(time.Hour), false),
	} {
		db := setupStageDB(t)
		g := newStageGenerator(db)
		snap := []model.AlertWhitelist{wl}
		g.dbWhitelist.Store(&snap)

		generateOnce(g, "/opt/bin/backup.sh")

		rows := alertsOf(t, db)
		if len(rows) != 1 || rows[0].Status != model.AlertStatusActive {
			t.Fatalf("%s 的抑制规则不应生效，应产生 active 告警: %+v", name, rows)
		}
	}
}

// 证据之外的命中照常告警：抑制的是 backup.sh，换成别的进程不受影响。
func TestSuppressionIsScopedToEvidence(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	wl := []model.AlertWhitelist{suppressionRule(7, "backup.sh", time.Now().Add(time.Hour), true)}
	g.dbWhitelist.Store(&wl)

	generateOnce(g, "/tmp/payload")

	rows := alertsOf(t, db)
	if len(rows) != 1 || rows[0].Status != model.AlertStatusActive {
		t.Fatalf("证据之外的命中必须照常告警: %+v", rows)
	}
}

// 被抑制的命中与人在处置的告警分属两组，互不吞并。
func TestSuppressedAndActiveAreSeparateGroups(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	wl := []model.AlertWhitelist{suppressionRule(7, "backup.sh", time.Now().Add(time.Hour), true)}
	g.dbWhitelist.Store(&wl)

	generateOnce(g, "/tmp/payload")       // active
	generateOnce(g, "/opt/bin/backup.sh") // suppressed

	rows := alertsOf(t, db)
	if len(rows) != 2 || rows[0].GroupKey == rows[1].GroupKey {
		t.Fatalf("应为两组各一条: %+v", rows)
	}
}

// critical 告警不认只写「规则 + 主机」的抑制规则。
func TestCriticalNeedsEvidenceToBeSuppressed(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	at := model.ToLocalTime(time.Now().Add(time.Hour))
	wl := []model.AlertWhitelist{{ID: 9, RuleID: "cel-47", HostID: "h1", ExpiresAt: &at, Enabled: true}}
	g.dbWhitelist.Store(&wl)

	rule := model.DetectionRule{Name: "c", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh}
	rule.ID = 47
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/tmp/x"})

	rows := alertsOf(t, db)
	if len(rows) != 1 || rows[0].Status != model.AlertStatusActive {
		t.Fatalf("没有具体证据的抑制规则不能压下 critical 告警: %+v", rows)
	}
}
