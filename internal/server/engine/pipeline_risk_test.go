package engine

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/risk"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 流水线把命中转成风险输入：规则号换成告警表写法；阶段声明的战术优先，否则由技术推出；
// 影子规则不计；时间取事件时间。
func TestObserveRisk(t *testing.T) {
	got := make(chan model.RiskDecision, 8)
	acc := risk.New(risk.Deps{
		KnownHost: func(string) bool { return true },
		Persist:   func(d model.RiskDecision) error { got <- d; return nil },
	}, risk.ModeShadow, zap.NewNop())
	p := (&Pipeline{}).WithRisk(acc)
	at := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	ev := func() PipelineEvent {
		return PipelineEvent{HostID: "h1", EventTime: at, fieldsCache: &fieldsCache{done: true,
			fields: map[string]string{"exe": "/usr/bin/id"}}}
	}

	p.observeRisk("cel_rule", ev(), Alert{RuleID: "44", Severity: "medium", ATTCKTechnique: "T1033", Shadow: true})
	p.observeRisk("cel_rule", ev(), Alert{RuleID: "9", Severity: "medium", ATTCKTactic: "T1053.003", ATTCKTechnique: "T1053.003"})
	p.observeRisk("sequence", ev(), Alert{RuleID: "3", Severity: "medium", ATTCKTechnique: "T1068"})
	p.observeRisk("ioc", ev(), Alert{RuleID: "ioc-ip", Severity: "high", ATTCKTactic: "TA0011"})

	select {
	case d := <-got:
		// 没有进程号，只计入主机层；主机层候选要三个战术：TA0003（cel-9）、TA0004（seq-3）、TA0011（ioc-ip）。
		if d.Level != risk.LevelHost || d.Tactics != "TA0003,TA0004,TA0011" {
			t.Fatalf("战术或层级不对: %+v", d)
		}
		if !time.Time(d.FirstSeen).Equal(at) {
			t.Fatalf("应使用事件时间，得 %v", time.Time(d.FirstSeen))
		}
	case <-time.After(time.Second):
		t.Fatal("三个战术应在主机层产生一条候选判断")
	}
}
