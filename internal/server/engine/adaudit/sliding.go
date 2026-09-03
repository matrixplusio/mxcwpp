package adaudit

import (
	"strings"
	"sync"
	"time"
)

// slidingCounter 简易滑窗计数 (line per key, ts 列表).
type slidingCounter struct {
	mu     sync.Mutex
	window time.Duration
	data   map[string][]time.Time
}

func newSlidingCounter(window time.Duration) *slidingCounter {
	return &slidingCounter{
		window: window,
		data:   make(map[string][]time.Time),
	}
}

// IncrAndGet 增 1 + 返当前窗口内计数.
func (s *slidingCounter) IncrAndGet(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-s.window)
	ts := s.data[key]
	// 清过期
	i := 0
	for ; i < len(ts); i++ {
		if ts[i].After(cutoff) {
			break
		}
	}
	ts = ts[i:]
	ts = append(ts, now)
	s.data[key] = ts
	return len(ts)
}

// DistinctPrefix 数有多少不同 key 以 prefix 开头 (Kerberoasting SPN count).
func (s *slidingCounter) DistinctPrefix(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	cutoff := time.Now().Add(-s.window)
	for k, ts := range s.data {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		// 检该 key 是否窗口内仍有 entry
		for _, t := range ts {
			if t.After(cutoff) {
				n++
				break
			}
		}
	}
	return n
}

// Cleanup 周期清空过期数据 (调用方 30s 1 次).
func (s *slidingCounter) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-s.window)
	for k, ts := range s.data {
		i := 0
		for ; i < len(ts); i++ {
			if ts[i].After(cutoff) {
				break
			}
		}
		if i == len(ts) {
			delete(s.data, k)
		} else if i > 0 {
			s.data[k] = ts[i:]
		}
	}
}
