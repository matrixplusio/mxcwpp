package alertbus

import (
	"errors"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

type fakeNotifier struct {
	calls      int
	categories []model.NotifyCategory
	sent       bool
	err        error
}

func (f *fakeNotifier) SendCategoryAlertNotification(c model.NotifyCategory, _ *notify.AlertData) (bool, error) {
	f.calls++
	f.categories = append(f.categories, c)
	return f.sent, f.err
}

func newTestPublisher(cfg Config, n *fakeNotifier, clock func() time.Time) *Publisher {
	p := New(nil, nil, cfg)
	p.notifier = n
	if clock != nil {
		p.now = clock
	}
	return p
}

func sampleEvent() Event {
	return Event{
		Category: model.NotifyCategoryKubeAlert,
		Source:   "kube_baseline",
		HostID:   "h-1",
		Severity: "critical",
		Title:    "特权容器",
		DedupKey: "kube_baseline|h-1|priv",
	}
}

// TestPublish_DefaultOff 零值 Config 必须全部关闭。
// 这五条链路此前从未通知过，默认开会在上线当晚淹没值班。
func TestPublish_DefaultOff(t *testing.T) {
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{}, n, nil)

	if got := p.Publish(sampleEvent()); got != OutcomeCategoryDisabled {
		t.Errorf("outcome = %s, want %s", got, OutcomeCategoryDisabled)
	}
	if n.calls != 0 {
		t.Errorf("未开启的类别不应发送，实际调用 %d 次", n.calls)
	}
}

// TestPublish_EnabledCategoryOnly 只有被灰度开启的类别才通知，其余仍静默入库。
func TestPublish_EnabledCategoryOnly(t *testing.T) {
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	if got := p.Publish(sampleEvent()); got != OutcomeNotified {
		t.Fatalf("outcome = %s, want %s", got, OutcomeNotified)
	}
	other := sampleEvent()
	other.Category = model.NotifyCategoryDetection
	other.DedupKey = "other"
	if got := p.Publish(other); got != OutcomeCategoryDisabled {
		t.Errorf("未开启类别 outcome = %s, want %s", got, OutcomeCategoryDisabled)
	}
	if n.calls != 1 {
		t.Errorf("只应发送 1 次，实际 %d", n.calls)
	}
}

// TestPublish_SeverityFloor 低于最低等级不通知；未知等级按最低处理，宁可不打扰。
func TestPublish_SeverityFloor(t *testing.T) {
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
		MinSeverity:       "high",
	}, n, nil)

	for _, tc := range []struct {
		severity string
		want     Outcome
	}{
		{"critical", OutcomeNotified},
		{"high", OutcomeNotified},
		{"medium", OutcomeBelowSeverity},
		{"low", OutcomeBelowSeverity},
		{"", OutcomeBelowSeverity},
		{"bogus", OutcomeBelowSeverity},
	} {
		e := sampleEvent()
		e.Severity = tc.severity
		e.DedupKey = "sev-" + tc.severity // 避开抑制
		if got := p.Publish(e); got != tc.want {
			t.Errorf("severity=%q outcome = %s, want %s", tc.severity, got, tc.want)
		}
	}
}

// TestPublish_Suppression 抑制窗口内的重复告警只通知一次，窗口过后恢复。
func TestPublish_Suppression(t *testing.T) {
	n := &fakeNotifier{sent: true}
	now := time.Unix(1700000000, 0)
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
		SuppressWindow:    30 * time.Minute,
	}, n, func() time.Time { return now })

	if got := p.Publish(sampleEvent()); got != OutcomeNotified {
		t.Fatalf("首次 outcome = %s", got)
	}
	now = now.Add(29 * time.Minute)
	if got := p.Publish(sampleEvent()); got != OutcomeSuppressed {
		t.Errorf("窗口内 outcome = %s, want %s", got, OutcomeSuppressed)
	}
	now = now.Add(2 * time.Minute) // 累计 31 分钟，超出窗口
	if got := p.Publish(sampleEvent()); got != OutcomeNotified {
		t.Errorf("窗口外 outcome = %s, want %s", got, OutcomeNotified)
	}
	if n.calls != 2 {
		t.Errorf("应发送 2 次，实际 %d", n.calls)
	}
}

// TestPublish_SuppressionIsPerIdentity 不同告警不得互相抑制。
func TestPublish_SuppressionIsPerIdentity(t *testing.T) {
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	a, b := sampleEvent(), sampleEvent()
	b.DedupKey = "kube_baseline|h-2|priv"
	if got := p.Publish(a); got != OutcomeNotified {
		t.Fatalf("a outcome = %s", got)
	}
	if got := p.Publish(b); got != OutcomeNotified {
		t.Errorf("不同身份不应被抑制，outcome = %s", got)
	}
}

// TestPublish_NoRecipient 类别开了却没有匹配的通知配置，等于开了个通不到人的口子。
// 必须与"已送达"区分，否则运维会以为通知在工作。
func TestPublish_NoRecipient(t *testing.T) {
	n := &fakeNotifier{sent: false}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	if got := p.Publish(sampleEvent()); got != OutcomeNoRecipient {
		t.Errorf("outcome = %s, want %s", got, OutcomeNoRecipient)
	}
}

// TestPublish_NoRecipientDoesNotSuppress 没送达任何人时不得记入抑制，
// 否则配好通知配置后仍要干等一个窗口才可能收到。
func TestPublish_NoRecipientDoesNotSuppress(t *testing.T) {
	n := &fakeNotifier{sent: false}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	p.Publish(sampleEvent())
	n.sent = true // 运维补上了通知配置
	if got := p.Publish(sampleEvent()); got != OutcomeNotified {
		t.Errorf("outcome = %s, want %s（未送达不应进入抑制窗口）", got, OutcomeNotified)
	}
}

// TestPublish_ErrorDoesNotSuppress 发送失败同样不得记入抑制，否则一次抖动会静默吞掉
// 整个窗口内的同类告警。
func TestPublish_ErrorDoesNotSuppress(t *testing.T) {
	n := &fakeNotifier{err: errors.New("webhook timeout")}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	if got := p.Publish(sampleEvent()); got != OutcomeError {
		t.Fatalf("outcome = %s, want %s", got, OutcomeError)
	}
	n.err = nil
	n.sent = true
	if got := p.Publish(sampleEvent()); got != OutcomeNotified {
		t.Errorf("outcome = %s, want %s（发送失败不应进入抑制窗口）", got, OutcomeNotified)
	}
}

// TestPublish_Invalid 缺少必填字段的事件必须被明确拒绝，而不是当作普通未发送。
func TestPublish_Invalid(t *testing.T) {
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
	}, n, nil)

	noCategory := sampleEvent()
	noCategory.Category = ""
	if got := p.Publish(noCategory); got != OutcomeInvalid {
		t.Errorf("缺 category outcome = %s, want %s", got, OutcomeInvalid)
	}
	noTitle := sampleEvent()
	noTitle.Title = "   "
	if got := p.Publish(noTitle); got != OutcomeInvalid {
		t.Errorf("缺 title outcome = %s, want %s", got, OutcomeInvalid)
	}
	if n.calls != 0 {
		t.Errorf("不合法事件不应发送，实际 %d 次", n.calls)
	}
}

// TestDedupIdentityFallback 调用方漏填 DedupKey 时仍要有稳定身份，否则完全不抑制。
func TestDedupIdentityFallback(t *testing.T) {
	e := Event{Source: "anomaly", HostID: "h-1", Title: "异常"}
	if e.dedupIdentity() != "anomaly|h-1|异常" {
		t.Errorf("fallback 身份 = %q", e.dedupIdentity())
	}
	e.DedupKey = "explicit"
	if e.dedupIdentity() != "explicit" {
		t.Errorf("显式 DedupKey 应优先，实际 %q", e.dedupIdentity())
	}
}
