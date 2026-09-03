package celengine

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// trackerWindowDuration 滑动窗口时长（count_recent 统计窗口）
	trackerWindowDuration = 5 * time.Minute

	// trackerKnownTTL first_seen 的判定窗口：超过这个时长没再出现的值，
	// 下次出现重新算"首次"。known 集合必须有界，而值本身没有自然的生命周期，
	// 只能靠时间淘汰——否则每主机的取值集合随运行时长单调累积。
	trackerKnownTTL = 24 * time.Hour

	// trackerKnownCap 每主机已知值上限（防单机噪声打爆内存的硬闸）。
	// 主机之间的取值集合规模差异很大：多数主机只有少量稳定取值，
	// 而运行大量短生命周期进程或频繁对外连接的主机，取值数量会高出数个量级。
	// 上限设得太低会让这类主机常态触顶、first_seen 长期降级；
	// 键改存哈希后单条成本很低，放宽上限的内存代价可以接受。
	trackerKnownCap = 250000

	// trackerKnownCleanupInterval known 集合的淘汰周期。
	// 与窗口清理分开：known 的条目数可能比滑动窗口高出数个量级，
	// 按 5 分钟频率全量遍历会长时间持锁阻塞热路径 Observe。
	trackerKnownCleanupInterval = 30 * time.Minute
)

// hashTrackerKey 计算 "field:value" 的 64 位 FNV-1a 哈希。
//
// known 集合只做存在性判断，从不读回原值，因此没有必要保存完整字符串。
// 键形如 "remote_addr:<地址>" 或 "file_path:<长路径>"，保存原串的单条内存开销
// 比定长哈希高出一个量级。64 位空间下碰撞概率可忽略，
// 且一次碰撞的后果仅是漏掉一次 first_seen 判定，不会误报。
//
// 手写循环而非 hash/fnv：后者每次调用都要分配 hash.Hash64，
// 而这里位于每事件都会走的热路径上。
func hashTrackerKey(field, value string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(field); i++ {
		h ^= uint64(field[i])
		h *= prime64
	}
	h ^= uint64(':')
	h *= prime64
	for i := 0; i < len(value); i++ {
		h ^= uint64(value[i])
		h *= prime64
	}
	return h
}

// EventTracker 维护事件频率统计和首次出现追踪
// 用于 CEL 规则中的 recent_*_count 和 first_seen_* 变量
type EventTracker struct {
	mu      sync.Mutex
	windows map[string]map[string][]time.Time // hostID → "field:value" → timestamps
	known   map[string]map[uint64]time.Time   // hostID → hash("field:value") → 最后出现时间
	logger  *zap.Logger
}

// NewEventTracker 创建事件追踪器
func NewEventTracker(logger *zap.Logger) *EventTracker {
	return &EventTracker{
		windows: make(map[string]map[string][]time.Time),
		known:   make(map[string]map[uint64]time.Time),
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
	keyHash := hashTrackerKey(field, value)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// --- first_seen ---
	hostKnown := t.known[hostID]
	if hostKnown == nil {
		hostKnown = make(map[uint64]time.Time, 64)
		t.known[hostID] = hostKnown
	}
	lastSeen, seen := hostKnown[keyHash]
	switch {
	case seen:
		// 记录过：距上次出现超过 TTL 才重新算首次，并刷新时间戳
		firstSeen = now.Sub(lastSeen) > trackerKnownTTL
		hostKnown[keyHash] = now
	case len(hostKnown) < trackerKnownCap:
		firstSeen = true
		hostKnown[keyHash] = now
	default:
		// 触顶：这个值记不下来，就不能声称它是首次出现——否则它每次出现
		// 都会重新判定为首次，把 first_seen_* 规则变成持续误报源。
		// 宁可漏报也不制造告警风暴；触顶本身由 Stats 暴露给运维。
		firstSeen = false
	}

	// --- sliding window ---
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

// CleanupKnown 淘汰超过 TTL 未再出现的 known 条目，返回淘汰数量。
// 与 Cleanup 分开调用：known 的条目数比滑动窗口高两个数量级，
// 全量遍历需要持锁，不能按窗口清理的频率跑。
func (t *EventTracker) CleanupKnown() int {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	var removed int
	for hostID, hostKnown := range t.known {
		for keyHash, lastSeen := range hostKnown {
			if now.Sub(lastSeen) > trackerKnownTTL {
				delete(hostKnown, keyHash)
				removed++
			}
		}
		if len(hostKnown) == 0 {
			delete(t.known, hostID)
		}
	}

	return removed
}

// KnownAtCap 返回 known 集合已触顶的主机数。
// 触顶主机的 first_seen 判定已降级为恒 false（不报），需要运维介入。
func (t *EventTracker) KnownAtCap() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	var n int
	for _, hostKnown := range t.known {
		if len(hostKnown) >= trackerKnownCap {
			n++
		}
	}
	return n
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
