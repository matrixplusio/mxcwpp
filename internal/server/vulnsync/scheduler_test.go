package vulnsync

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// fakeSource 记录 Fetch 收到的 since，用于断言 watermark 传递。
type fakeSource struct {
	name string
	mu   sync.Mutex
	got  time.Time
	seen bool
}

func (f *fakeSource) Name() string                    { return f.name }
func (f *fakeSource) Confidence() advisory.Confidence { return advisory.ConfidenceHigh }
func (f *fakeSource) Fetch(_ context.Context, since time.Time) ([]*advisory.Advisory, error) {
	f.mu.Lock()
	f.got, f.seen = since, true
	f.mu.Unlock()
	return nil, nil
}
func (f *fakeSource) sinceSeen() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got, f.seen
}

// fakeStore 提供固定 watermark。
type fakeStore struct {
	wm    map[string]time.Time
	saved map[string]time.Time
	mu    sync.Mutex
}

func (s *fakeStore) Load(src string) (time.Time, bool) {
	t, ok := s.wm[src]
	return t, ok
}
func (s *fakeStore) Save(src string, t time.Time) error {
	s.mu.Lock()
	if s.saved == nil {
		s.saved = map[string]time.Time{}
	}
	s.saved[src] = t
	s.mu.Unlock()
	return nil
}

// TestScheduler_LoadsWatermarkOnStart 锁定：重启后 fetch 用持久 watermark 做 since（增量），
// 而非零值全量——这是防 vulnsync 重启 since=zero 全量重拉打爆 Kafka 的核心。
func TestScheduler_LoadsWatermarkOnStart(t *testing.T) {
	wm := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{name: "rhsa"}
	store := &fakeStore{wm: map[string]time.Time{"rhsa": wm}}
	sch := NewScheduler(
		map[string]advisory.Source{"rhsa": src},
		nil, nil,
		[]SourceSchedule{{Name: "rhsa", Interval: time.Hour}},
		nil, store,
	)

	// TriggerNow 用 watermark 作 since 调 fetchOne（publisher nil → Fetch 后即返回，足够断言 since）。
	sch.TriggerNow(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, seen := src.sinceSeen(); seen {
			if !got.Equal(wm) {
				t.Fatalf("fetch since = %v, want persisted watermark %v (重启应增量拉取)", got, wm)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fetch 未被调用")
}

// TestScheduler_NoStoreFullFetch 无 store 时 since 为零值（全量），保持向后兼容。
func TestScheduler_NoStoreFullFetch(t *testing.T) {
	src := &fakeSource{name: "rhsa"}
	sch := NewScheduler(
		map[string]advisory.Source{"rhsa": src},
		nil, nil,
		[]SourceSchedule{{Name: "rhsa", Interval: time.Hour}},
		nil, nil,
	)
	sch.TriggerNow(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, seen := src.sinceSeen(); seen {
			if !got.IsZero() {
				t.Fatalf("无 store 时 since 应为零值(全量), got %v", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fetch 未被调用")
}
