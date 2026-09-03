package celengine

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestObserveFirstSeenWithinTTL 同一值在 TTL 内重复出现只算一次首次
func TestObserveFirstSeenWithinTTL(t *testing.T) {
	tr := NewEventTracker(zap.NewNop())

	if _, first := tr.Observe("h1", "exe", "/bin/sh"); !first {
		t.Fatal("首次观测应返回 firstSeen=true")
	}
	if _, first := tr.Observe("h1", "exe", "/bin/sh"); first {
		t.Fatal("TTL 内重复观测不应再判为首次")
	}
}

// TestObserveFirstSeenAfterTTL 超过 TTL 未出现的值，再次出现重新算首次
func TestObserveFirstSeenAfterTTL(t *testing.T) {
	tr := NewEventTracker(zap.NewNop())
	tr.Observe("h1", "exe", "/bin/sh")

	// 把最后出现时间回拨到 TTL 之前
	tr.mu.Lock()
	tr.known["h1"][hashTrackerKey("exe", "/bin/sh")] = time.Now().Add(-trackerKnownTTL - time.Minute)
	tr.mu.Unlock()

	if _, first := tr.Observe("h1", "exe", "/bin/sh"); !first {
		t.Fatal("超过 TTL 后再次出现应重新判为首次")
	}
}

// TestObserveAtCapDoesNotReportFirstSeen 触顶后新值不得被判为首次，
// 否则每次出现都会重新判定，把 first_seen 规则变成持续误报源。
func TestObserveAtCapDoesNotReportFirstSeen(t *testing.T) {
	tr := NewEventTracker(zap.NewNop())

	tr.mu.Lock()
	hostKnown := make(map[uint64]time.Time, trackerKnownCap)
	for i := 0; i < trackerKnownCap; i++ {
		hostKnown[uint64(i)] = time.Now()
	}
	tr.known["h1"] = hostKnown
	tr.mu.Unlock()

	if got := len(tr.known["h1"]); got < trackerKnownCap {
		t.Fatalf("测试前置条件不满足: known=%d < cap=%d", got, trackerKnownCap)
	}

	if _, first := tr.Observe("h1", "exe", "/never/seen/before"); first {
		t.Fatal("known 触顶时新值不应被判为首次出现")
	}
	if tr.KnownAtCap() != 1 {
		t.Fatalf("KnownAtCap 应报告 1 台触顶主机，得到 %d", tr.KnownAtCap())
	}
}

// TestCleanupKnownEvictsExpired known 淘汰只清理超过 TTL 的条目
func TestCleanupKnownEvictsExpired(t *testing.T) {
	tr := NewEventTracker(zap.NewNop())
	tr.Observe("h1", "exe", "/bin/fresh")
	tr.Observe("h1", "exe", "/bin/stale")

	tr.mu.Lock()
	tr.known["h1"][hashTrackerKey("exe", "/bin/stale")] = time.Now().Add(-trackerKnownTTL - time.Minute)
	tr.mu.Unlock()

	if removed := tr.CleanupKnown(); removed != 1 {
		t.Fatalf("应淘汰 1 条过期记录，实际 %d", removed)
	}
	if _, _, knownKeys := tr.Stats(); knownKeys != 1 {
		t.Fatalf("淘汰后应剩 1 条 known，实际 %d", knownKeys)
	}
}

// TestCleanupKnownDropsEmptyHost 主机条目全部淘汰后应移除该主机
func TestCleanupKnownDropsEmptyHost(t *testing.T) {
	tr := NewEventTracker(zap.NewNop())
	tr.Observe("h1", "exe", "/bin/stale")

	tr.mu.Lock()
	tr.known["h1"][hashTrackerKey("exe", "/bin/stale")] = time.Now().Add(-trackerKnownTTL - time.Minute)
	tr.mu.Unlock()

	tr.CleanupKnown()

	tr.mu.Lock()
	_, exists := tr.known["h1"]
	tr.mu.Unlock()
	if exists {
		t.Fatal("known 条目清空后应移除该主机，否则 hostID 维度仍会无限累积")
	}
}

// TestHashTrackerKeyDistinguishesFieldBoundary field 与 value 的拼接点必须参与哈希，
// 否则 ("ab","c") 与 ("a","bc") 会碰撞成同一个键。
func TestHashTrackerKeyDistinguishesFieldBoundary(t *testing.T) {
	if hashTrackerKey("ab", "c") == hashTrackerKey("a", "bc") {
		t.Fatal("field/value 边界未参与哈希，不同键碰撞")
	}
	// 热路径上的常见字段组合两两不得碰撞——一次碰撞就会漏掉一次 first_seen
	keys := []struct{ f, v string }{
		{"exe", "/bin/sh"}, {"exe", "/bin/bash"},
		{"remote_addr", "10.0.0.1:443"}, {"remote_addr", "10.0.0.1:80"},
		{"file_path", "/etc/passwd"}, {"file_path", "/etc/shadow"},
	}
	seen := make(map[uint64]string, len(keys))
	for _, k := range keys {
		h := hashTrackerKey(k.f, k.v)
		if prev, dup := seen[h]; dup {
			t.Fatalf("哈希碰撞: %s:%s 与 %s", k.f, k.v, prev)
		}
		seen[h] = k.f + ":" + k.v
	}
}
