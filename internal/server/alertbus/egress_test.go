package alertbus

import (
	"sync"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type recordingEgress struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingEgress) Forward(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingEgress) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// TestEgress_NotSubjectToSuppression 外发不受抑制窗口影响。
//
// 抑制是为了少打扰人，不是为了让客户 SIEM 少收记录。若外发也走抑制，
// 客户侧就会出现平台单方面造成的缺口，而他们无从知道少了什么。
func TestEgress_NotSubjectToSuppression(t *testing.T) {
	eg := &recordingEgress{}
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
		SuppressWindow:    time.Hour,
	}, n, nil).WithEgress(eg)

	for i := 0; i < 3; i++ {
		p.Publish(sampleEvent())
	}
	if n.calls != 1 {
		t.Errorf("通知应被抑制为 1 次，实际 %d", n.calls)
	}
	if eg.count() != 3 {
		t.Errorf("外发应全量 3 条，实际 %d（客户 SIEM 出现缺口）", eg.count())
	}
}

// TestEgress_NotSubjectToCategoryGate 类别未灰度开启时仍要外发。
// 灰度控制的是"要不要叫醒人"，不是"要不要留档"。
func TestEgress_NotSubjectToCategoryGate(t *testing.T) {
	eg := &recordingEgress{}
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{}, n, nil).WithEgress(eg) // 全部类别关闭

	if got := p.Publish(sampleEvent()); got != OutcomeCategoryDisabled {
		t.Fatalf("outcome = %s", got)
	}
	if n.calls != 0 {
		t.Error("未开启类别不应通知")
	}
	if eg.count() != 1 {
		t.Errorf("外发不应被类别开关拦截，实际 %d 条", eg.count())
	}
}

// TestEgress_NotSubjectToSeverityFloor 低于通知等级门槛的告警仍要外发。
func TestEgress_NotSubjectToSeverityFloor(t *testing.T) {
	eg := &recordingEgress{}
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryKubeAlert: true},
		MinSeverity:       "critical",
	}, n, nil).WithEgress(eg)

	e := sampleEvent()
	e.Severity = "low"
	if got := p.Publish(e); got != OutcomeBelowSeverity {
		t.Fatalf("outcome = %s", got)
	}
	if eg.count() != 1 {
		t.Errorf("低等级告警同样要外发，实际 %d 条", eg.count())
	}
}

// TestEgress_EgressOnlySkipsNotification alerts 表那条链路自带通知，
// 接进来只为外发；若也走通知，值班会对同一条告警收到两次。
func TestEgress_EgressOnlySkipsNotification(t *testing.T) {
	eg := &recordingEgress{}
	n := &fakeNotifier{sent: true}
	p := newTestPublisher(Config{
		EnabledCategories: map[model.NotifyCategory]bool{model.NotifyCategoryDetection: true},
	}, n, nil).WithEgress(eg)

	e := sampleEvent()
	e.Category = model.NotifyCategoryDetection
	e.EgressOnly = true
	if got := p.Publish(e); got != OutcomeEgressOnly {
		t.Fatalf("outcome = %s, want %s", got, OutcomeEgressOnly)
	}
	if n.calls != 0 {
		t.Error("EgressOnly 不应触发通知（否则重复打扰）")
	}
	if eg.count() != 1 {
		t.Errorf("EgressOnly 必须外发，实际 %d 条", eg.count())
	}
}

// TestEgress_InvalidEventNotForwarded 不合法事件不外发，
// 避免把残缺记录塞进客户 SIEM。
func TestEgress_InvalidEventNotForwarded(t *testing.T) {
	eg := &recordingEgress{}
	p := newTestPublisher(Config{}, &fakeNotifier{}, nil).WithEgress(eg)

	bad := sampleEvent()
	bad.Title = "  "
	if got := p.Publish(bad); got != OutcomeInvalid {
		t.Fatalf("outcome = %s", got)
	}
	if eg.count() != 0 {
		t.Error("不合法事件不应外发")
	}
}

// TestAsyncEgress_DropsWhenFullRatherThanBlocking 队列满时丢弃而非阻塞。
//
// 底层发送是同步的（持锁写 socket、超时 5 秒）。若在队列满时阻塞，
// 一个不可达的 SIEM 就能拖住整条检测流水线。丢弃必须计量且可见。
func TestAsyncEgress_DropsWhenFullRatherThanBlocking(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	a := NewAsyncEgress(nil, 1, func(Event) { <-block }) // sink 永久阻塞
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			a.Forward(sampleEvent())
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("队列满时 Forward 阻塞了，SIEM 不可达会拖住检测流水线")
	}
}
