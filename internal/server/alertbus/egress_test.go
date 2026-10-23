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

// TestEgress_ForwardsEveryPublish 外发在入队之前、全量进行。
//
// 类别灰度、等级门槛、抑制窗口都在分发器里，管的是「要不要叫醒人」，不是「要不要留档」。
// 重复的、类别未开的、低等级的告警都必须外发，否则客户 SIEM 出现平台单方面造成的缺口。
func TestEgress_ForwardsEveryPublish(t *testing.T) {
	db := newTestDB(t)
	eg := &recordingEgress{}
	p := New(db, nil).WithEgress(eg)
	low := sampleEvent()
	low.Severity = "low"
	for _, e := range []Event{sampleEvent(), sampleEvent(), low} {
		if got := p.Publish(e); got != OutcomeQueued {
			t.Fatalf("outcome = %s", got)
		}
	}
	if eg.count() != 3 {
		t.Errorf("外发应全量 3 条，实际 %d", eg.count())
	}
}

// TestEgress_EgressOnlySkipsNotification alerts 表那条链路自带通知，
// 接进来只为外发；若也入队，值班会对同一条告警收到两次。
func TestEgress_EgressOnlySkipsNotification(t *testing.T) {
	db := newTestDB(t)
	eg := &recordingEgress{}
	e := sampleEvent()
	e.Category = model.NotifyCategoryDetection
	e.EgressOnly = true
	if got := New(db, nil).WithEgress(eg).Publish(e); got != OutcomeEgressOnly {
		t.Fatalf("outcome = %s, want %s", got, OutcomeEgressOnly)
	}
	var n int64
	db.Model(&model.AlertNotifyEvent{}).Count(&n)
	if n != 0 {
		t.Error("EgressOnly 不应入队（否则重复打扰）")
	}
	if eg.count() != 1 {
		t.Errorf("EgressOnly 必须外发，实际 %d 条", eg.count())
	}
}

// TestEgress_InvalidEventNotForwarded 不合法事件不外发，避免把残缺记录塞进客户 SIEM。
func TestEgress_InvalidEventNotForwarded(t *testing.T) {
	eg := &recordingEgress{}
	bad := sampleEvent()
	bad.Title = "  "
	if got := New(newTestDB(t), nil).WithEgress(eg).Publish(bad); got != OutcomeInvalid {
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
