package alertbus

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1) // :memory: 每条连接各是一个库
	}
	if err := db.AutoMigrate(&model.AlertNotifyEvent{}, &model.NotificationDelivery{}, &model.NotificationDedup{}); err != nil {
		t.Fatal(err)
	}
	return db
}

type fakeDeliverer struct {
	mu       sync.Mutex
	channels []model.Notification
	fail     map[uint]bool
	failErr  error // 非空时失败返回它，用于构造带地址的错误
	calls    map[uint]int
}

func (f *fakeDeliverer) EnrichHost(*notify.EventMessage) {}
func (f *fakeDeliverer) MatchChannels(*notify.EventMessage) ([]model.Notification, error) {
	return f.channels, nil
}
func (f *fakeDeliverer) DeliverEvent(n *model.Notification, _ *notify.EventMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[uint]int{}
	}
	f.calls[n.ID]++
	if f.fail[n.ID] {
		if f.failErr != nil {
			return f.failErr
		}
		return errors.New("webhook 500")
	}
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)} }
func enabled(cats ...model.NotifyCategory) Config {
	m := map[model.NotifyCategory]bool{}
	for _, c := range cats {
		m[c] = true
	}
	return Config{EnabledCategories: m}
}

func newDispatcher(db *gorm.DB, cfg Config, f *fakeDeliverer, c *clock) *Dispatcher {
	d := NewDispatcher(db, nil, cfg)
	d.notify = f
	d.now = c.now
	return d
}

func publish(t *testing.T, db *gorm.DB, c *clock, e Event) {
	t.Helper()
	p := New(db, nil)
	p.now = c.now
	if got := p.Publish(e); got != OutcomeQueued {
		t.Fatalf("Publish = %s, want queued", got)
	}
}

func sampleEvent() Event {
	return Event{
		Category: model.NotifyCategoryKubeAlert,
		Source:   "kube_baseline",
		HostID:   "h-1",
		Severity: "CRITICAL",
		Title:    "特权容器",
		DedupKey: "kube_baseline|h-1|priv",
	}
}

func outcomes(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var rows []model.NotificationDelivery
	db.Order("id").Find(&rows)
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Outcome
	}
	return out
}

func eventStatus(t *testing.T, db *gorm.DB) model.AlertNotifyEvent {
	t.Helper()
	var ev model.AlertNotifyEvent
	if err := db.Order("id desc").First(&ev).Error; err != nil {
		t.Fatal(err)
	}
	return ev
}

// 发布只入队：不在发布方进程里发送，也不在那里做灰度判断。
func TestPublish_Enqueues(t *testing.T) {
	db, c := newTestDB(t), newClock()
	publish(t, db, c, sampleEvent())
	ev := eventStatus(t, db)
	if ev.Status != model.NotifyEventPending || ev.Severity != "critical" || ev.DedupKey != "kube_baseline|h-1|priv" {
		t.Fatalf("入队内容不对: %+v", ev)
	}
}

func TestPublish_EgressOnlyNotQueued(t *testing.T) {
	db := newTestDB(t)
	e := sampleEvent()
	e.EgressOnly = true
	if got := New(db, nil).Publish(e); got != OutcomeEgressOnly {
		t.Fatalf("got %s", got)
	}
	var n int64
	db.Model(&model.AlertNotifyEvent{}).Count(&n)
	if n != 0 {
		t.Fatal("EgressOnly 不应入队，否则 alerts 链路的告警会被通知两次")
	}
}

func TestPublish_Invalid(t *testing.T) {
	db := newTestDB(t)
	if got := New(db, nil).Publish(Event{Title: "无类别"}); got != OutcomeInvalid {
		t.Fatalf("got %s", got)
	}
}

// 零值 Config 必须全部关闭：这些链路此前从未通知过，默认开会在上线当晚淹没值班。
func TestDispatch_DefaultOff(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}}
	publish(t, db, c, sampleEvent())
	newDispatcher(db, Config{}, f, c).DispatchOnce()
	if len(f.calls) != 0 {
		t.Fatal("类别未开启却发送了")
	}
	if got := outcomes(t, db); len(got) != 1 || got[0] != model.DeliveryCategoryDisabled {
		t.Fatalf("投递记录 = %v", got)
	}
	if eventStatus(t, db).Status != model.NotifyEventDone {
		t.Fatal("事件应标记完成")
	}
}

func TestDispatch_SeverityFloor(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}}
	e := sampleEvent()
	e.Severity = "medium"
	publish(t, db, c, e)
	newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c).DispatchOnce()
	if got := outcomes(t, db); len(got) != 1 || got[0] != model.DeliveryBelowSeverity {
		t.Fatalf("投递记录 = %v", got)
	}
}

// 类别开了却没有渠道：等于开了个通不到人的口子，必须留下记录。
func TestDispatch_NoRecipient(t *testing.T) {
	db, c := newTestDB(t), newClock()
	publish(t, db, c, sampleEvent())
	newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), &fakeDeliverer{}, c).DispatchOnce()
	if got := outcomes(t, db); len(got) != 1 || got[0] != model.DeliveryNoRecipient {
		t.Fatalf("投递记录 = %v", got)
	}
}

// 去重按 (告警身份, 渠道) 存库：同一告警窗口内对同一渠道只发一次，不同告警互不影响，窗口过后再发。
func TestDispatch_SuppressionPerIdentityAndWindow(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}}
	d := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)

	publish(t, db, c, sampleEvent())
	publish(t, db, c, sampleEvent())
	other := sampleEvent()
	other.DedupKey = "kube_baseline|h-2|priv"
	publish(t, db, c, other)
	d.DispatchOnce()
	if f.calls[1] != 2 {
		t.Fatalf("应发 2 次（两个不同告警），实际 %d", f.calls[1])
	}

	c.add(31 * time.Minute)
	publish(t, db, c, sampleEvent())
	d.DispatchOnce()
	if f.calls[1] != 3 {
		t.Fatalf("窗口过后应再次通知，实际共 %d 次", f.calls[1])
	}
	got := outcomes(t, db)
	want := []string{model.DeliverySent, model.DeliverySuppressed, model.DeliverySent, model.DeliverySent}
	if len(got) != len(want) {
		t.Fatalf("投递记录 = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("投递记录 = %v, want %v", got, want)
		}
	}
}

// 一个渠道失败只重试它自己，已送达的渠道不会被重复打扰；失败不能占用去重窗口。
func TestDispatch_RetryOnlyFailedChannel(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}, {ID: 2}}, fail: map[uint]bool{2: true}}
	d := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)
	publish(t, db, c, sampleEvent())

	d.DispatchOnce()
	ev := eventStatus(t, db)
	if ev.Status != model.NotifyEventPending || ev.Attempts != 1 || !ev.NextAttemptAt.Equal(c.t.Add(time.Minute)) {
		t.Fatalf("失败后应排期重试: %+v", ev)
	}

	d.DispatchOnce() // 未到重试时间，不应处理
	if f.calls[2] != 1 {
		t.Fatalf("未到期就重试了: %d", f.calls[2])
	}

	f.fail[2] = false
	c.add(2 * time.Minute)
	d.DispatchOnce()
	if f.calls[1] != 1 || f.calls[2] != 2 {
		t.Fatalf("重试应只补发失败渠道: %v", f.calls)
	}
	if eventStatus(t, db).Status != model.NotifyEventDone {
		t.Fatal("补发成功后事件应完成")
	}
}

func TestDispatch_GivesUpAfterRetries(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}, fail: map[uint]bool{1: true}}
	d := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)
	publish(t, db, c, sampleEvent())
	for i := 0; i < 6; i++ {
		d.DispatchOnce()
		c.add(time.Hour)
	}
	ev := eventStatus(t, db)
	if ev.Status != model.NotifyEventFailed || f.calls[1] != len(retryBackoff)+1 {
		t.Fatalf("应在 %d 次后放弃: status=%s calls=%d", len(retryBackoff)+1, ev.Status, f.calls[1])
	}
}

// 两个分发器同时跑（多副本或重启交接），同一事件只处理一次。
func TestDispatch_ClaimIsExclusive(t *testing.T) {
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}}
	publish(t, db, c, sampleEvent())
	a := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)
	b := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)
	var ev model.AlertNotifyEvent
	db.First(&ev)
	if !a.claim(&ev, c.t) || b.claim(&ev, c.t) {
		t.Fatal("同一事件被认领了两次")
	}
	// 认领者崩溃：租约到期后可被接管
	c.add(claimLease + time.Second)
	if !b.claim(&ev, c.t) {
		t.Fatal("租约到期后应能接管")
	}
}

func TestDedupIdentityFallback(t *testing.T) {
	e := Event{Source: "behavior", HostID: "h-1", Title: "偏离"}
	if got := e.dedupIdentity(); got != "behavior|h-1|偏离" {
		t.Fatalf("got %q", got)
	}
}

// TestDispatch_FailureRecordsOmitWebhookURL 发送实现返回的错误即使带着完整地址，
// 写进投递记录和事件表的也只能是脱敏后的文本——分发器这一层自己兜底，不依赖发送实现自觉。
func TestDispatch_FailureRecordsOmitWebhookURL(t *testing.T) {
	const token = "0f1e2d3c-token-must-not-leak"
	db, c := newTestDB(t), newClock()
	f := &fakeDeliverer{channels: []model.Notification{{ID: 1}}, fail: map[uint]bool{1: true},
		failErr: errors.New(`Post "https://open.example.com/open-apis/bot/v2/hook/` + token + `": context deadline exceeded`)}
	d := newDispatcher(db, enabled(model.NotifyCategoryKubeAlert), f, c)
	publish(t, db, c, sampleEvent())
	d.DispatchOnce()

	var deliveries []model.NotificationDelivery
	db.Find(&deliveries)
	if len(deliveries) == 0 {
		t.Fatal("应有失败的投递记录")
	}
	for _, r := range deliveries {
		if strings.Contains(r.Error, token) || strings.Contains(r.Error, "/hook/") {
			t.Fatalf("投递记录泄露了 webhook 地址: %s", r.Error)
		}
	}
	if ev := eventStatus(t, db); strings.Contains(ev.LastError, token) || !strings.Contains(ev.LastError, "deadline exceeded") {
		t.Fatalf("事件表 last_error 应脱敏且保留原因: %s", ev.LastError)
	}
}
