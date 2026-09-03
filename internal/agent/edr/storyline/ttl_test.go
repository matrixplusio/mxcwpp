package storyline

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestAbsoluteTTL_LongLivedProcessGetsNewStory 常驻进程的 story 不得被活跃度无限续期。
//
// 回归 2026-08 事故：命中规则的是 nginx worker 这类常驻进程，它持续产生事件，
// 每次 Assign/Inherit 都刷新 lastSeen，2 小时静默期永远到不了。观察到单条
// story 存活 半个月、累计 千万级条事件，最终把 storyline_events 撑到数百 GB。
func TestAbsoluteTTL_LongLivedProcessGetsNewStory(t *testing.T) {
	tr := NewTracker(zap.NewNop())

	const pid = 4242
	first := tr.Assign(pid)
	if first == "" {
		t.Fatal("首次分配应返回 story_id")
	}

	// 模拟该进程持续活跃了超过绝对上限：createdAt 拨回到上限之前，
	// lastSeen 保持"刚刚"——这正是常驻进程的真实形态。
	tr.mu.Lock()
	tr.entries[pid].createdAt = time.Now().Add(-absoluteTTL - time.Minute)
	tr.entries[pid].lastSeen = time.Now()
	tr.mu.Unlock()

	second := tr.Assign(pid)
	if second == first {
		t.Errorf("story 存活已超绝对上限 %v，再次命中规则应换新 ID，"+
			"否则常驻进程会把全部日常活动挂在同一条故事线下", absoluteTTL)
	}
	if second == "" {
		t.Error("换新后必须仍返回有效 story_id")
	}
}

// TestAbsoluteTTL_ActiveStoryWithinWindowKeepsID 上限之内的活跃 story 必须保持同一 ID，
// 否则同一次攻击会被拆成多条互不关联的故事线。
func TestAbsoluteTTL_ActiveStoryWithinWindowKeepsID(t *testing.T) {
	tr := NewTracker(zap.NewNop())

	const pid = 5150
	first := tr.Assign(pid)

	tr.mu.Lock()
	tr.entries[pid].createdAt = time.Now().Add(-absoluteTTL / 2)
	tr.mu.Unlock()

	if second := tr.Assign(pid); second != first {
		t.Error("未超绝对上限的 story 应保持同一 ID")
	}
}

// TestInherit_ChildCarriesParentCreatedAt 子进程必须继承父进程的创建时间。
//
// 若子进程用自己的 createdAt，父进程只要不停 fork 就能让同一个 story_id
// 靠源源不断的"新条目"续期到天荒地老 —— 绝对 TTL 形同虚设。
func TestInherit_ChildCarriesParentCreatedAt(t *testing.T) {
	tr := NewTracker(zap.NewNop())

	const ppid, pid = 100, 101
	parentStory := tr.Assign(ppid)

	born := time.Now().Add(-absoluteTTL / 2)
	tr.mu.Lock()
	tr.entries[ppid].createdAt = born
	tr.mu.Unlock()

	if got := tr.Inherit(ppid, pid); got != parentStory {
		t.Fatalf("子进程应继承父进程 story_id，得到 %q 期望 %q", got, parentStory)
	}

	tr.mu.RLock()
	childBorn := tr.entries[pid].createdAt
	tr.mu.RUnlock()

	if !childBorn.Equal(born) {
		t.Errorf("子进程 createdAt 应继承父进程的 %v，实际 %v —— "+
			"否则父进程不停 fork 即可绕过绝对 TTL", born, childBorn)
	}
}

// TestCleanup_EvictsByAgeEvenWhenActive Cleanup 的两条判据互相独立：
// 静默太久要清，存在太久也要清（哪怕一直活跃）。
func TestCleanup_EvictsByAgeEvenWhenActive(t *testing.T) {
	tr := NewTracker(zap.NewNop())

	const oldActive, freshActive = 200, 201
	tr.Assign(oldActive)
	tr.Assign(freshActive)

	tr.mu.Lock()
	// 一直活跃，但出生太早
	tr.entries[oldActive].createdAt = time.Now().Add(-absoluteTTL - time.Hour)
	tr.entries[oldActive].lastSeen = time.Now()
	tr.mu.Unlock()

	tr.Cleanup()

	if tr.Lookup(oldActive) != "" {
		t.Error("存活超过绝对上限的条目应被清理，即使它仍在活跃")
	}
	if tr.Lookup(freshActive) == "" {
		t.Error("窗口内的正常条目不应被清理")
	}
}

// TestCleanup_StillEvictsIdle 原有的静默清理逻辑不能被破坏。
func TestCleanup_StillEvictsIdle(t *testing.T) {
	tr := NewTracker(zap.NewNop())

	const idle = 300
	tr.Assign(idle)

	tr.mu.Lock()
	tr.entries[idle].lastSeen = time.Now().Add(-entryTTL - time.Minute)
	tr.mu.Unlock()

	tr.Cleanup()

	if tr.Lookup(idle) != "" {
		t.Error("静默超过 entryTTL 的条目仍应被清理")
	}
}
