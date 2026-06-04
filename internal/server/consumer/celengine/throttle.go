package celengine

import (
	"sync"
	"time"
)

// HitThrottler 限制 (host, rule) 维度的告警生成频率。
//
// 现状：alerts 表已对 (rule, host) 去重（resultID = cel-{ruleID}-{hostID}），
// 单 alert 行只累加 HitCount。但每次命中仍会写 storyline_events、触发通知节流判断、
// 走 SIEM forward、调用 BDE/IForest（未来）等。当某 host 一个规则疯狂命中
// （prod 实测 nginx 触发 c2_high_risk_port 单 host 31k 次），即使 alert 表
// 只有 1 条，下游链路仍被打爆。
//
// Throttler 在 alert generator 入口拦截：单位时间窗内同 (host, rule) 命中
// 超过 burstThreshold 后，标记为 throttled，调用方应跳过重写入。
//
// 设计要点：
//   - 内存 LRU + 滑动窗口，不依赖 DB
//   - 容量上限 lruCapacity，超出按 LRU 淘汰
//   - 计数器周期重置（每 refillWindow）
//   - 线程安全
type HitThrottler struct {
	mu             sync.Mutex
	buckets        map[string]*hitBucket // key: ruleID|hostID
	lruOrder       []string              // 最久未访问在前
	burstThreshold int
	refillWindow   time.Duration
	capacity       int
}

type hitBucket struct {
	count          int
	windowStart    time.Time
	lastSeen       time.Time
	throttledUntil time.Time
}

// NewHitThrottler 创建告警频率限制器。
//
// burstThreshold: 窗口内命中超过此值开启节流（建议 50-100）。
// refillWindow:   计数窗口长度（建议 1 分钟）。
// throttleDur:    超阈后静默时长（建议 10 分钟，与 alert.go notifyThrottleWindow 解耦）。
// capacity:       LRU 上限（建议 10000，覆盖 prod 209 host × 94 rule ≈ 20k 组合）。
func NewHitThrottler(burstThreshold int, refillWindow time.Duration, capacity int) *HitThrottler {
	return &HitThrottler{
		buckets:        make(map[string]*hitBucket),
		lruOrder:       make([]string, 0, capacity),
		burstThreshold: burstThreshold,
		refillWindow:   refillWindow,
		capacity:       capacity,
	}
}

// Allow 返回 true 表示允许该 (hostID, ruleID) 继续生成告警；false 表示已被节流。
//
// 副作用：每次调用更新内部计数器，超阈后开启 10min 静默窗。
func (t *HitThrottler) Allow(hostID, ruleID string, now time.Time) bool {
	key := ruleID + "|" + hostID
	t.mu.Lock()
	defer t.mu.Unlock()

	b, ok := t.buckets[key]
	if !ok {
		b = &hitBucket{windowStart: now}
		t.buckets[key] = b
		t.lruOrder = append(t.lruOrder, key)
		t.evictIfNeededLocked()
	}
	b.lastSeen = now

	// 静默窗口期内直接拒绝
	if !b.throttledUntil.IsZero() && now.Before(b.throttledUntil) {
		return false
	}

	// 窗口翻页
	if now.Sub(b.windowStart) > t.refillWindow {
		b.windowStart = now
		b.count = 0
		b.throttledUntil = time.Time{}
	}

	b.count++
	if b.count > t.burstThreshold {
		// 超阈：开启静默 10 倍窗口（rule of thumb，可配置化）
		b.throttledUntil = now.Add(t.refillWindow * 10)
		return false
	}
	return true
}

// evictIfNeededLocked 在 capacity 满时 LRU 淘汰一个最早条目。
// 调用方需持锁。简单 O(n) 实现，capacity=10k 规模可接受。
func (t *HitThrottler) evictIfNeededLocked() {
	if len(t.lruOrder) <= t.capacity {
		return
	}
	// 找最久未 lastSeen 的 key
	oldestKey := ""
	var oldestTime time.Time
	for k, b := range t.buckets {
		if oldestKey == "" || b.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastSeen
		}
	}
	if oldestKey != "" {
		delete(t.buckets, oldestKey)
		// 重建 lruOrder（简化实现，可优化为双向链表）
		newOrder := make([]string, 0, len(t.lruOrder)-1)
		for _, k := range t.lruOrder {
			if k != oldestKey {
				newOrder = append(newOrder, k)
			}
		}
		t.lruOrder = newOrder
	}
}

// Size 返回当前 bucket 数（用于 metrics / 监控）。
func (t *HitThrottler) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}
