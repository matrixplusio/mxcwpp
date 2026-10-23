package celengine

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func campaignDetector(t *testing.T) (*ScanDetector, *gorm.DB) {
	t.Helper()
	db := setupScanAlertDB(t)
	if err := db.Exec(`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, hostname TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO hosts VALUES ('h1','web-01'), ('h2','web-02'), ('h3','db-01')`)
	return &ScanDetector{db: db, logger: zap.NewNop()}, db
}

func alertByResultID(t *testing.T, db *gorm.DB, resultID string) model.Alert {
	t.Helper()
	var a model.Alert
	if err := db.Where("result_id = ?", resultID).First(&a).Error; err != nil {
		t.Fatalf("找不到告警 %s: %v", resultID, err)
	}
	return a
}

// 同一外部来源扫了多台主机：生成一条来源级 critical 告警，各主机上的单条扫描告警一并升级。
//
// 单主机告警按端口数定级时只是 medium，各自孤立地看就是普通扫描；
// 合起来才是针对暴露面的探测。级别不跟着升，研判的人先看到的那条仍会被放过去。
func TestRaiseCampaignAlertEscalatesMembers(t *testing.T) {
	d, db := campaignDetector(t)
	const src = "203.0.113.7"
	upsertScanAlert(t, db, "h1", src, "扫描", "medium")
	upsertScanAlert(t, db, "h2", src, "扫描", "medium")
	upsertScanAlert(t, db, "h3", "198.51.100.9", "别的来源", "medium")

	now := model.ToLocalTime(time.Now())
	d.raiseCampaignAlert(src, []string{"h1", "h2"}, now)

	c := alertByResultID(t, db, campaignAlertResultID(src))
	if c.Severity != "critical" || c.RuleID != scanCampaignRuleID || c.HostID != "h1" {
		t.Errorf("来源级告警不对: severity=%s rule=%s host=%s", c.Severity, c.RuleID, c.HostID)
	}
	if !strings.Contains(c.Title, "2 台主机") || !strings.Contains(c.Description, "web-01") || !strings.Contains(c.Description, "web-02") {
		t.Errorf("标题与描述要写明波及的主机: %q / %q", c.Title, c.Description)
	}
	for _, h := range []string{"h1", "h2"} {
		if got := alertByResultID(t, db, scanAlertResultID(h, src)).Severity; got != "critical" {
			t.Errorf("%s 上的单主机告警应升到 critical，得 %s", h, got)
		}
	}
	if got := alertByResultID(t, db, scanAlertResultID("h3", "198.51.100.9")).Severity; got != "medium" {
		t.Errorf("别的来源的告警不应被波及，得 %s", got)
	}

	// 第三台加入：并进同一条来源级告警，标题刷新，不新开一条。
	upsertScanAlert(t, db, "h3", src, "扫描", "medium")
	d.raiseCampaignAlert(src, []string{"h1", "h2", "h3"}, now)
	var n int64
	db.Model(&model.Alert{}).Where("rule_id = ?", scanCampaignRuleID).Count(&n)
	if n != 1 {
		t.Errorf("同一来源应只有一条来源级告警，得 %d", n)
	}
	if c := alertByResultID(t, db, campaignAlertResultID(src)); !strings.Contains(c.Title, "3 台主机") {
		t.Errorf("标题应随主机数刷新: %q", c.Title)
	}
}

// 升上去的级别不被后续命中降回去：跨资产窗口过后，同一来源的下一次单主机命中按端口数只算 medium。
func TestPersistScanAlertNeverDowngrades(t *testing.T) {
	_, db := campaignDetector(t)
	upsertScanAlert(t, db, "h1", "203.0.113.7", "第一次", "critical")
	upsertScanAlert(t, db, "h1", "203.0.113.7", "窗口过后的再次命中", "medium")

	a := alertByResultID(t, db, scanAlertResultID("h1", "203.0.113.7"))
	if a.Severity != "critical" {
		t.Errorf("级别被降回 %s", a.Severity)
	}
	if a.HitCount != 2 || a.Description != "窗口过后的再次命中" {
		t.Errorf("命中仍应累加并刷新描述: hit=%d desc=%q", a.HitCount, a.Description)
	}
}

func TestBumpSeverity(t *testing.T) {
	for in, want := range map[string]string{"low": "medium", "medium": "high", "high": "critical", "critical": "critical"} {
		if got := bumpSeverity(in); got != want {
			t.Errorf("bumpSeverity(%s)=%s，期望 %s", in, got, want)
		}
	}
}
