package celengine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newGateWithRows(t *testing.T, rows ...model.RuleCriticalAdmission) *CriticalGate {
	t.Helper()
	db := setupStageDB(t)
	if err := db.AutoMigrate(&model.RuleCriticalAdmission{}); err != nil {
		t.Fatalf("migrate admissions: %v", err)
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed admission: %v", err)
		}
	}
	return NewCriticalGate(db, zap.NewNop())
}

func TestCriticalGateCap(t *testing.T) {
	g := newGateWithRows(t,
		model.RuleCriticalAdmission{RuleID: "cel-1", Allowed: true},
		model.RuleCriticalAdmission{RuleID: "cel-2", Allowed: false},
	)
	cases := []struct {
		name, ruleID, in, want string
	}{
		{"准入的规则保持 critical", "cel-1", "critical", "critical"},
		{"被收回准入的规则降为 high", "cel-2", "critical", "high"},
		{"清单里没有的规则降为 high", "cel-99", "critical", "high"},
		{"只管 critical，其余级别不动", "cel-2", "medium", "medium"},
	}
	for _, c := range cases {
		if got := g.Cap(c.ruleID, c.in); got != c.want {
			t.Errorf("%s：Cap(%s, %s) = %s，期望 %s", c.name, c.ruleID, c.in, got, c.want)
		}
	}
}

// 清单读不到、或还没写进来时不能限制级别：那会把所有 critical 静默压掉。
func TestCriticalGateNotReadyDoesNotCap(t *testing.T) {
	var nilGate *CriticalGate
	if got := nilGate.Cap("cel-1", "critical"); got != "critical" {
		t.Errorf("未启用时不应限制，得 %s", got)
	}

	empty := newGateWithRows(t)
	if got := empty.Cap("cel-1", "critical"); got != "critical" {
		t.Errorf("清单为空（初始清单尚未写入）时不应限制，得 %s", got)
	}

	// 表不存在：加载失败，同样按未就绪处理。
	noTable := NewCriticalGate(setupStageDB(t), zap.NewNop())
	if got := noTable.Cap("cel-1", "critical"); got != "critical" {
		t.Errorf("清单加载失败时不应限制，得 %s", got)
	}
}

// 加载失败沿用上一份快照，不能退回「不限制」。
func TestCriticalGateKeepsSnapshotOnReloadFailure(t *testing.T) {
	g := newGateWithRows(t, model.RuleCriticalAdmission{RuleID: "cel-1", Allowed: true})
	if err := g.db.Exec("DROP TABLE rule_critical_admissions").Error; err != nil {
		t.Fatalf("drop: %v", err)
	}
	g.reload()
	if got := g.Cap("cel-2", "critical"); got != "high" {
		t.Errorf("加载失败后应沿用旧快照继续限制，得 %s", got)
	}
}

// 告警落库的级别走准入；清单里没有的规则写着 critical 也只能落成 high。
func TestGenerateAppliesCriticalGate(t *testing.T) {
	g := newGateWithRows(t, model.RuleCriticalAdmission{RuleID: "cel-1", Allowed: true})
	gen := newStageGenerator(g.db)
	gen.SetCriticalGate(g)

	rules := []model.DetectionRule{
		{ID: 1, Name: "准入规则", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh, Builtin: true},
		{ID: 2, Name: "未准入规则", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh, Builtin: true},
	}
	gen.Generate("h1", rules, map[string]string{"exe": "/bin/x"})

	got := map[string]string{}
	var rows []struct{ RuleID, Severity string }
	if err := g.db.Table("alerts").Select("rule_id, severity").Scan(&rows).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, r := range rows {
		got[r.RuleID] = r.Severity
	}
	if got["cel-1"] != "critical" || got["cel-2"] != "high" {
		t.Fatalf("级别不符：%v，期望 cel-1=critical、cel-2=high", got)
	}
}

// 攻击链告警同样走准入。
func TestSequenceAppliesCriticalGate(t *testing.T) {
	g := newGateWithRows(t, model.RuleCriticalAdmission{RuleID: "seq-1", Allowed: true})
	gen := newStageGenerator(g.db)
	gen.SetCriticalGate(g)

	gen.GenerateFromSequence("h1", model.SequenceRule{ID: 1, Name: "准入链", Severity: "critical"}, map[string]string{})
	gen.GenerateFromSequence("h1", model.SequenceRule{ID: 2, Name: "未准入链", Severity: "critical"}, map[string]string{})

	var sev1, sev2 string
	g.db.Table("alerts").Select("severity").Where("rule_id = ?", "seq-1").Scan(&sev1)
	g.db.Table("alerts").Select("severity").Where("rule_id = ?", "seq-2").Scan(&sev2)
	if sev1 != "critical" || sev2 != "high" {
		t.Fatalf("seq-1=%s seq-2=%s，期望 critical / high", sev1, sev2)
	}
}

// 大范围命中时：已获 critical 准入的规则只聚合、不压制，汇总告警也不降级。
// 勒索软件借配置管理同时下发，就是「大多数主机同时命中一条 critical 规则」的样子。
func TestFleetGuardKeepsAdmittedCriticalAlerts(t *testing.T) {
	g := newGateWithRows(t, model.RuleCriticalAdmission{RuleID: "cel-7", Allowed: true})
	gen := newStageGenerator(g.db)
	gen.SetCriticalGate(g)
	gen.fleet = newFleetGuard()
	registerHosts(gen, 10)
	seedActiveHosts(gen.fleet, 10, time.Now())

	rules := []model.DetectionRule{
		{ID: 7, Name: "已准入的 critical", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh, Builtin: true},
		{ID: 8, Name: "未准入的 critical", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh, Builtin: true},
	}
	hosts := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"}
	for _, h := range hosts {
		gen.Generate(h, rules, map[string]string{"exe": "/bin/x"})
	}

	count := func(ruleID, status string) int64 {
		var n int64
		g.db.Table("alerts").Where("rule_id = ? AND status = ? AND host_id <> ?", ruleID, status, fleetHostID).Count(&n)
		return n
	}
	if got := count("cel-7", string(model.AlertStatusActive)); got != int64(len(hosts)) {
		t.Errorf("已准入的 critical 规则各主机告警应全部保留，得 %d/%d", got, len(hosts))
	}
	if got := count("cel-7", string(model.AlertStatusSuppressed)); got != 0 {
		t.Errorf("已准入的 critical 规则不该有被压制的告警，得 %d", got)
	}
	// 未准入的实际落成 high，照旧按规则失真处理：超过阈值之后的主机被压制。
	if got := count("cel-8", string(model.AlertStatusSuppressed)); got == 0 {
		t.Error("未准入规则超过阈值后的命中应记为 suppressed")
	}

	sev := func(ruleID string) string {
		var s string
		g.db.Table("alerts").Select("severity").Where("host_id = ? AND rule_id = ?", fleetHostID, ruleID).Scan(&s)
		return s
	}
	if got := sev("cel-7"); got != "critical" {
		t.Errorf("汇总告警不该因为命中面大而降级，得 %q", got)
	}
	if got := sev("cel-8"); got != "high" {
		t.Errorf("未准入规则的汇总告警应与各主机告警同级（high），得 %q", got)
	}
}

// 汇总告警按间隔刷新，不是每条命中都去改同一行。
func TestFleetGuardThrottlesSummaryRefresh(t *testing.T) {
	f := newFleetGuard()
	now := time.Unix(1760000000, 0)
	seedActiveHosts(f, 20, now)
	refreshes := 0
	for i := 0; i < 200; i++ {
		_, _, _, _, refresh := f.observeAndThrottle("cel-1", fmt.Sprintf("h%d", i%20), now.Add(time.Duration(i)*100*time.Millisecond))
		if refresh {
			refreshes++
		}
	}
	if refreshes != 1 {
		t.Fatalf("20 秒内应只刷新 1 次，得 %d 次", refreshes)
	}
	if _, _, _, _, refresh := f.observeAndThrottle("cel-1", "h1", now.Add(fleetAlertRefreshGap+time.Second)); !refresh {
		t.Fatal("过了刷新间隔应再刷新一次")
	}
}

// 被压过级的告警在详情里留下规则原本声明的级别。
func TestCappedAlertKeepsDeclaredSeverity(t *testing.T) {
	g := newGateWithRows(t, model.RuleCriticalAdmission{RuleID: "cel-1", Allowed: true})
	gen := newStageGenerator(g.db)
	gen.SetCriticalGate(g)
	gen.Generate("h1", []model.DetectionRule{
		{ID: 2, Name: "未准入", Severity: "critical", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh, Builtin: true},
	}, map[string]string{"exe": "/bin/x"})
	var actual string
	g.db.Table("alerts").Select("actual").Where("rule_id = ?", "cel-2").Scan(&actual)
	if !strings.Contains(actual, `"declared_severity":"critical"`) {
		t.Fatalf("详情里应留下声明的级别，得 %s", actual)
	}
}
