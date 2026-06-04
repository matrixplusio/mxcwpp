package celengine

import (
	"fmt"
	"testing"
	"time"
)

func TestHitThrottler_AllowUnderThreshold(t *testing.T) {
	tr := NewHitThrottler(10, time.Minute, 100)
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !tr.Allow("host1", "rule1", now) {
			t.Fatalf("hit %d should be allowed", i+1)
		}
	}
}

func TestHitThrottler_BlockOverThreshold(t *testing.T) {
	tr := NewHitThrottler(10, time.Minute, 100)
	now := time.Now()
	for i := 0; i < 10; i++ {
		tr.Allow("host1", "rule1", now)
	}
	// 第 11 次超过阈值
	if tr.Allow("host1", "rule1", now) {
		t.Fatal("11th hit should be blocked")
	}
}

func TestHitThrottler_DifferentHostsIndependent(t *testing.T) {
	tr := NewHitThrottler(5, time.Minute, 100)
	now := time.Now()
	for i := 0; i < 5; i++ {
		tr.Allow("host1", "rule1", now)
	}
	if tr.Allow("host1", "rule1", now) {
		t.Fatal("host1 should be throttled")
	}
	// host2 应该不受影响
	if !tr.Allow("host2", "rule1", now) {
		t.Fatal("host2 should not be affected by host1 throttle")
	}
}

func TestHitThrottler_DifferentRulesIndependent(t *testing.T) {
	tr := NewHitThrottler(5, time.Minute, 100)
	now := time.Now()
	for i := 0; i < 5; i++ {
		tr.Allow("host1", "rule1", now)
	}
	if tr.Allow("host1", "rule1", now) {
		t.Fatal("rule1 should be throttled")
	}
	if !tr.Allow("host1", "rule2", now) {
		t.Fatal("rule2 should not be affected")
	}
}

func TestHitThrottler_WindowRollsOver(t *testing.T) {
	tr := NewHitThrottler(5, time.Minute, 100)
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		tr.Allow("host1", "rule1", t0)
	}
	if tr.Allow("host1", "rule1", t0) {
		t.Fatal("should be throttled at t0")
	}
	// 静默期 = window * 10 = 10min，10min 后窗口才解锁
	t1 := t0.Add(11 * time.Minute)
	if !tr.Allow("host1", "rule1", t1) {
		t.Fatal("should be allowed after throttle window expires")
	}
}

func TestHitThrottler_ThrottleWindowKeepsBlocking(t *testing.T) {
	tr := NewHitThrottler(5, time.Minute, 100)
	t0 := time.Now()
	for i := 0; i < 6; i++ {
		tr.Allow("host1", "rule1", t0)
	}
	// 静默窗 10 倍 refill window = 10min
	for i := 1; i <= 9; i++ {
		tn := t0.Add(time.Duration(i) * time.Minute)
		if tr.Allow("host1", "rule1", tn) {
			t.Fatalf("should still be throttled at t+%dmin", i)
		}
	}
}

func TestHitThrottler_LRUEviction(t *testing.T) {
	tr := NewHitThrottler(100, time.Minute, 10)
	now := time.Now()
	// 填满 11 个 key（容量 10），LRU 应淘汰 1 个
	for i := 0; i < 11; i++ {
		tr.Allow(fmt.Sprintf("host%d", i), "rule1", now.Add(time.Duration(i)*time.Second))
	}
	if got := tr.Size(); got != 10 {
		t.Fatalf("expected size 10 after eviction, got %d", got)
	}
}
