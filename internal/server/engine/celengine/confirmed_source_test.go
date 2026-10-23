package celengine

import (
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 自有情报库里的 IP 是我们自己确认过的攻击源：它连进来必须告警。
// 外部 feed 的入站命中被抑制是为了挡全网扫描的噪声，不能把这一类也一起挡掉。
func TestConfirmedSourceInboundAlerts(t *testing.T) {
	db := setupScanAlertDB(t)
	if err := db.Exec(`CREATE TABLE local_iocs (id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id TEXT DEFAULT 't-default', ioc_type TEXT, value TEXT, source TEXT, severity TEXT,
		description TEXT, ref_type TEXT, ref_id TEXT, enabled BOOLEAN, created_by TEXT,
		created_at TIMESTAMP, updated_at TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO local_iocs (ioc_type, value, enabled) VALUES ('ip','203.0.113.7',1), ('ip','203.0.113.8',0), ('hash','abc',1)`)

	m := NewIOCMatcher(db, zap.NewNop())
	m.reloadConfirmed()
	if !m.CheckConfirmedIP("203.0.113.7") {
		t.Fatal("已启用的自有情报 IP 应命中")
	}
	if m.CheckConfirmedIP("203.0.113.8") || m.CheckConfirmedIP("abc") || m.CheckConfirmedIP("198.51.100.1") {
		t.Error("停用的、非 IP 的、不在库里的都不应命中")
	}

	g := NewAlertGenerator(db, zap.NewNop())
	fields := map[string]string{"direction": "inbound", "event_type": "tcp_accept", "remote_addr": "203.0.113.7", "local_port": "8080"}
	g.GenerateFromConfirmedSource("h1", "203.0.113.7", fields)
	g.GenerateFromConfirmedSource("h1", "203.0.113.7", fields)

	var alerts []model.Alert
	db.Where("rule_id = ?", ConfirmedSourceRuleID).Find(&alerts)
	if len(alerts) != 1 {
		t.Fatalf("同一来源同一主机应只有一条告警，得 %d", len(alerts))
	}
	if a := alerts[0]; a.Severity != "critical" || a.Status != model.AlertStatusActive || a.HostID != "h1" {
		t.Errorf("告警不对: severity=%s status=%s host=%s", a.Severity, a.Status, a.HostID)
	}
}
