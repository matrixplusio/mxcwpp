package celengine

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// trackerWindowDuration 滑动窗口时长（count_recent 统计窗口）
	trackerWindowDuration = 5 * time.Minute

	// trackerKnownCap 每主机已知值上限（first_seen 追踪）
	trackerKnownCap = 50000
)

// EventTracker 维护事件频率统计和首次出现追踪
// 用于 CEL 规则中的 recent_*_count 和 first_seen_* 变量
type EventTracker struct {
	mu      sync.Mutex
	windows map[string]map[string][]time.Time // hostID → "field:value" → timestamps
	known   map[string]map[string]struct{}    // hostID → set of "field:value"
	logger  *zap.Logger
}

// NewEventTracker 创建事件追踪器
func NewEventTracker(logger *zap.Logger) *EventTracker {
	return &EventTracker{
		windows: make(map[string]map[string][]time.Time),
		known:   make(map[string]map[string]struct{}),
		logger:  logger,
	}
}

// Observe 记录一次事件观测，返回窗口内计数和是否首次出现
// 调用一次同时完成：检查 first_seen → 标记已知 → 记录时间戳 → 返回窗口计数
func (t *EventTracker) Observe(hostID, field, value string) (count int64, firstSeen bool) {
	if hostID == "" || value == "" {
		return 0, false
	}

	key := field + ":" + value

	t.mu.Lock()
	defer t.mu.Unlock()

	// --- first_seen ---
	hostKnown := t.known[hostID]
	if hostKnown == nil {
		hostKnown = make(map[string]struct{}, 64)
		t.known[hostID] = hostKnown
	}
	_, seen := hostKnown[key]
	firstSeen = !seen
	if !seen && len(hostKnown) < trackerKnownCap {
		hostKnown[key] = struct{}{}
	}

	// --- sliding window ---
	now := time.Now()
	hostWindows := t.windows[hostID]
	if hostWindows == nil {
		hostWindows = make(map[string][]time.Time, 16)
		t.windows[hostID] = hostWindows
	}

	cutoff := now.Add(-trackerWindowDuration)
	timestamps := hostWindows[key]

	// Evict expired
	firstValid := 0
	for firstValid < len(timestamps) && timestamps[firstValid].Before(cutoff) {
		firstValid++
	}
	if firstValid > 0 {
		timestamps = timestamps[firstValid:]
	}

	timestamps = append(timestamps, now)
	hostWindows[key] = timestamps

	count = int64(len(timestamps))
	return
}

// Cleanup 清理过期滑动窗口条目，释放内存
func (t *EventTracker) Cleanup() int {
	cutoff := time.Now().Add(-trackerWindowDuration)

	t.mu.Lock()
	defer t.mu.Unlock()

	var removed int
	for hostID, hostWindows := range t.windows {
		for key, timestamps := range hostWindows {
			firstValid := 0
			for firstValid < len(timestamps) && timestamps[firstValid].Before(cutoff) {
				firstValid++
			}
			if firstValid == len(timestamps) {
				delete(hostWindows, key)
				removed++
			} else if firstValid > 0 {
				hostWindows[key] = timestamps[firstValid:]
			}
		}
		if len(hostWindows) == 0 {
			delete(t.windows, hostID)
		}
	}

	return removed
}

// Stats 返回追踪器统计
func (t *EventTracker) Stats() (hosts int, windowKeys int, knownKeys int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	hosts = len(t.windows)
	for _, hw := range t.windows {
		windowKeys += len(hw)
	}
	for _, hk := range t.known {
		knownKeys += len(hk)
	}
	return
}
