package alertbus

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// sqlite 不认 MySQL 的 ON UPDATE，告警表、配置表、主机表按用到的列手工建。
func newBridgeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	for _, ddl := range []string{
		`CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT DEFAULT 't-default', result_id TEXT,
			host_id TEXT, rule_id TEXT, source TEXT, severity TEXT, title TEXT, description TEXT, actual TEXT, expected TEXT,
			fix_suggestion TEXT, status TEXT, first_seen_at DATETIME, last_seen_at DATETIME, last_notified_at DATETIME,
			notify_count INTEGER DEFAULT 0, resolve_reason TEXT, created_at DATETIME, updated_at DATETIME)`,
		"CREATE TABLE system_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT DEFAULT 't-default', `key` TEXT, value TEXT, category TEXT, description TEXT, created_at DATETIME, updated_at DATETIME)",
		`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, hostname TEXT, ipv4 TEXT, business_line TEXT, tags TEXT)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func addAlert(t *testing.T, db *gorm.DB, source, host, severity, status string, firstSeen time.Time, notified *time.Time) uint {
	t.Helper()
	if err := db.Exec(`INSERT INTO alerts (result_id, host_id, rule_id, source, severity, title, status, first_seen_at, last_seen_at, last_notified_at)
		VALUES (?, ?, 'r', ?, ?, ?, ?, ?, ?, ?)`,
		source+"|"+host+"|"+firstSeen.String(), host, source, severity, source+" 告警", status, firstSeen, firstSeen, notified).Error; err != nil {
		t.Fatal(err)
	}
	var id uint
	db.Raw("SELECT MAX(id) FROM alerts").Scan(&id)
	return id
}

func queued(t *testing.T, db *gorm.DB) []model.AlertNotifyEvent {
	t.Helper()
	var evs []model.AlertNotifyEvent
	db.Order("id").Find(&evs)
	return evs
}

// 首次启用时现存活跃告警视为已通知，否则上线瞬间把历史告警一次推满群。
func TestBridge_CutoverSkipsExistingActive(t *testing.T) {
	db, c := newBridgeDB(t), newClock()
	d := newDispatcher(db, Config{}, &fakeDeliverer{}, c)
	addAlert(t, db, model.AlertSourceDetection, "h1", "critical", "active", c.t.Add(-time.Hour), nil)
	if n := d.BridgeAlerts(); n != 0 {
		t.Fatalf("上线前已存在的活跃告警不应入队，实际 %d", n)
	}
	id := addAlert(t, db, model.AlertSourceDetection, "h1", "critical", "active", c.t, nil)
	if n := d.BridgeAlerts(); n != 1 {
		t.Fatalf("上线后新告警应入队，实际 %d", n)
	}
	evs := queued(t, db)
	if len(evs) != 1 || evs[0].Category != model.NotifyCategoryDetection || evs[0].RefTable != "alerts" || evs[0].RefID != itoa(id) {
		t.Fatalf("入队内容不对: %+v", evs)
	}
	if d.BridgeAlerts() != 0 {
		t.Fatal("同一告警不应重复入队")
	}
}

// 原地重新激活（基础设施恢复后再触发、Agent 再次离线）置空 last_notified_at 即重新通知。
func TestBridge_ReactivatedAlertNotifiedAgain(t *testing.T) {
	db, c := newBridgeDB(t), newClock()
	d := newDispatcher(db, Config{}, &fakeDeliverer{}, c)
	d.ensureCutover()
	id := addAlert(t, db, model.AlertSourcePrometheusInfra, "", "high", "active", c.t, nil)
	d.BridgeAlerts()
	db.Exec("UPDATE alerts SET last_notified_at = NULL WHERE id = ?", id)
	d.BridgeAlerts()
	if n := len(queued(t, db)); n != 2 {
		t.Fatalf("重新激活后应再入队一次，实际共 %d 条", n)
	}
}

// 命中白名单（suppressed）的告警不通知。
func TestBridge_SuppressedNotBridged(t *testing.T) {
	db, c := newBridgeDB(t), newClock()
	d := newDispatcher(db, Config{}, &fakeDeliverer{}, c)
	d.ensureCutover()
	addAlert(t, db, model.AlertSourceDetection, "h1", "critical", "suppressed", c.t, nil)
	if d.BridgeAlerts() != 0 {
		t.Fatal("被抑制的告警不应通知")
	}
}

func TestResolvedEvent_OnlyIfNotified(t *testing.T) {
	now := model.Now()
	if _, ok := ResolvedEvent(&model.Alert{Source: model.AlertSourceAgent, Title: "离线"}); ok {
		t.Fatal("从没通知过的告警不应发恢复")
	}
	e, ok := ResolvedEvent(&model.Alert{ID: 7, Source: model.AlertSourceAgent, Title: "离线", ResultID: "offline-h1",
		LastNotifiedAt: &now, ResolveReason: "Agent 已恢复上线"})
	if !ok || e.Kind != model.NotifyKindResolved || e.Category != model.NotifyCategoryAgentOffline ||
		!strings.HasSuffix(e.DedupKey, "|resolved") || e.Description != "Agent 已恢复上线" {
		t.Fatalf("恢复事件不对: %+v", e)
	}
}

// 历来就通知的类别不受灰度开关与全局最低等级约束，否则迁入统一出口后会集体静音。
func TestDispatch_NonOptInCategoryNotGated(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}}
	publish(t, db, c, Event{Category: model.NotifyCategoryInfraAlert, Source: "prom", Severity: "low", Title: "磁盘", DedupKey: "x"})
	newDispatcher(db, Config{}, f, c).DispatchOnce()
	if f.calls[1] != 1 {
		t.Fatalf("基础设施告警应照常发送，实际 %v / %v", f.calls, outcomes(t, db))
	}
}

// 日报按每个渠道自己的等级与主机范围统计；没有可报的就不发。
func TestDigest_PerChannelScope(t *testing.T) {
	db, c := newBridgeDB(t), newClock()
	db.Exec(`INSERT INTO hosts (host_id, hostname, business_line) VALUES ('ha', 'a', 'BL-A'), ('hb', 'b', 'BL-B')`)
	old := c.t.Add(-48 * time.Hour)
	addAlert(t, db, model.AlertSourceDetection, "ha", "critical", "active", old, &old)
	addAlert(t, db, model.AlertSourceDetection, "ha", "high", "active", old, &old)
	addAlert(t, db, model.AlertSourceDetection, "hb", "critical", "active", c.t, &c.t) // 未满 24 小时，不进日报

	f := &scopedDeliverer{fakeDeliverer: fakeDeliverer{channels: []model.Notification{{ID: 1}, {ID: 2}}},
		accept: map[uint]string{1: "ha", 2: "hb"}}
	d := newDispatcher(db, Config{}, &f.fakeDeliverer, c)
	d.notify = f
	c.t = time.Date(2026, 10, 9, 10, 0, 0, 0, time.Local)
	d.maybeScheduleDigest()
	d.maybeScheduleDigest() // 同一天只排一次
	d.DispatchOnce()

	if f.calls[1] != 1 || f.calls[2] != 0 {
		t.Fatalf("只有能看到超期告警的渠道收日报: %v", f.calls)
	}
	if !strings.Contains(f.lastTitle[1], "2 条") || !strings.Contains(f.lastDesc[1], "严重 1") {
		t.Fatalf("日报内容不对: %q / %q", f.lastTitle[1], f.lastDesc[1])
	}
	var n int64
	db.Model(&model.AlertNotifyEvent{}).Where("kind = ?", model.NotifyKindDigest).Count(&n)
	if n != int64(len(digestCategories)) {
		t.Fatalf("每类每天一条日报事件，实际 %d", n)
	}
}

// scopedDeliverer 按渠道只接收指定主机的告警，模拟业务线范围。
type scopedDeliverer struct {
	fakeDeliverer
	accept    map[uint]string
	lastTitle map[uint]string
	lastDesc  map[uint]string
}

func (s *scopedDeliverer) ChannelsFor(model.NotifyCategory) ([]model.Notification, error) {
	return s.channels, nil
}
func (s *scopedDeliverer) ChannelAccepts(n *model.Notification, hostID, _ string) bool {
	return s.accept[n.ID] == hostID
}
func (s *scopedDeliverer) DeliverEvent(n *model.Notification, m *notify.EventMessage) error {
	if s.lastTitle == nil {
		s.lastTitle, s.lastDesc = map[uint]string{}, map[uint]string{}
	}
	s.lastTitle[n.ID], s.lastDesc[n.ID] = m.Title, m.Description
	return s.fakeDeliverer.DeliverEvent(n, m)
}

func itoa(id uint) string {
	return strconv.FormatUint(uint64(id), 10)
}
