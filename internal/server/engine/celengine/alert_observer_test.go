package celengine

import (
	"testing"

	"go.uber.org/zap"
)

// 自己落库的检测路径要把「新开了一条告警」报给上层计数；并进已开告警的后续命中不重复报。
// 不报的话，按检测阶段统计的告警数对这些阶段永远是 0，「长期零产出」的守卫就一直误报。
func TestAlertObserverFiresOncePerNewAlert(t *testing.T) {
	db := setupScanAlertDB(t)
	g := NewAlertGenerator(db, zap.NewNop())
	var got []string
	g.SetAlertObserver(func(stage, ruleID, severity string) { got = append(got, stage+"|"+ruleID+"|"+severity) })

	fields := map[string]string{"direction": "inbound", "remote_addr": "203.0.113.7"}
	g.GenerateFromConfirmedSource("h1", "203.0.113.7", fields)
	g.GenerateFromConfirmedSource("h1", "203.0.113.7", fields)

	if len(got) != 1 || got[0] != "ioc|"+ConfirmedSourceRuleID+"|critical" {
		t.Errorf("应只在新开告警时报一次，得 %v", got)
	}
}
