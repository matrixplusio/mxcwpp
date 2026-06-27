package scheduler

import (
	"reflect"
	"testing"
)

func TestOrderTactics_KillChainOrderDedup(t *testing.T) {
	// 乱序 + 重复 + 空 + 未知 → 去重、kill-chain 排序、未知置末
	in := []string{"TA0011", "", "TA0001", "TA0002", "TA0001", "TA9999"}
	got := orderTactics(in)
	want := []string{"TA0001", "TA0002", "TA0011", "TA9999"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderTactics=%v want %v", got, want)
	}
}

func TestIsIncidentWorthy(t *testing.T) {
	cases := []struct {
		alerts, tactics int
		want            bool
	}{
		{1, 2, true},  // 跨2战术
		{3, 1, true},  // 3告警
		{2, 1, false}, // 都不够
		{1, 1, false},
		{5, 0, true},
	}
	for _, c := range cases {
		if got := isIncidentWorthy(c.alerts, c.tactics); got != c.want {
			t.Errorf("isIncidentWorthy(a=%d,t=%d)=%v want %v", c.alerts, c.tactics, got, c.want)
		}
	}
}

func TestAggregateRisk_MultiTacticBoostAndCap(t *testing.T) {
	if r := aggregateRisk(50, 1); r != 50 {
		t.Errorf("单战术不 boost: %v want 50", r)
	}
	if r := aggregateRisk(50, 2); r != 60 { // 50*1.2
		t.Errorf("多战术 boost: %v want 60", r)
	}
	if r := aggregateRisk(90, 3); r != 100 { // 90*1.2=108 封顶 100
		t.Errorf("封顶: %v want 100", r)
	}
}

func TestSummarizeIncident(t *testing.T) {
	alerts := []incidentAlert{
		{ID: 1, Severity: "medium", RiskScore: 40, ATTCKTactic: "TA0011"},
		{ID: 2, Severity: "critical", RiskScore: 90, ATTCKTactic: "TA0001"},
		{ID: 3, Severity: "high", RiskScore: 60, ATTCKTactic: "TA0001"}, // 重复战术
	}
	sev, risk, tactics, ids := summarizeIncident(alerts)
	if sev != "critical" {
		t.Errorf("maxSeverity=%s want critical", sev)
	}
	if risk != 90 {
		t.Errorf("maxRisk=%v want 90", risk)
	}
	if !reflect.DeepEqual(tactics, []string{"TA0001", "TA0011"}) {
		t.Errorf("tactics=%v want [TA0001 TA0011]", tactics)
	}
	if !reflect.DeepEqual(ids, []string{"1", "2", "3"}) {
		t.Errorf("ids=%v", ids)
	}
}
