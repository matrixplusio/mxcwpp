// Package storyline implements the Agent-side CausalTracker for attack storyline
// correlation. When a detection rule matches, the tracker assigns a story_id (UUID)
// to the triggering process. All subsequent events from that process and its
// descendants inherit the story_id, enabling the Server to reconstruct the full
// attack narrative from a single correlated event stream.
package storyline

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// maxEntries caps the tracker size to prevent unbounded growth.
	maxEntries = 10000
	// entryTTL controls how long a PID→story mapping is retained after last activity.
	entryTTL = 2 * time.Hour
	// absoluteTTL 是一条 story 从创建起的绝对存活上限，与活跃度无关。
	//
	// entryTTL 是"静默多久后清理"，而 lastSeen 每次 Assign/Inherit 都会刷新。
	// 命中规则的若是常驻进程（nginx worker、监控采集器、systemd 服务），它持续有
	// 事件，lastSeen 就持续被推后，2 小时的静默期永远到不了 —— 该进程树此后
	// 每一条事件都会一直带着同一个 story_id。观察到最长一条存活半个月、
	// 攒了 千万级条事件。
	//
	// 攻击叙事本身有时间尺度：一次入侵的侦察→提权→驻留通常在数小时内完成。
	// 超过一天还在延续的，已经不是"同一个故事"，而是把一个长期运行的进程的
	// 全部日常活动挂在了一个 ID 下。到期后清理，进程若再次命中规则会重新分配新 ID。
	absoluteTTL = 24 * time.Hour
)

type entry struct {
	storyID  string
	lastSeen time.Time
	// createdAt 用于 absoluteTTL 判定，不随活跃度刷新。
	createdAt time.Time
}

// Tracker maintains PID → story_id mappings for the local host.
// Thread-safe; designed for high-frequency event path.
type Tracker struct {
	mu      sync.RWMutex
	entries map[int32]*entry // pid → story entry
	logger  *zap.Logger
}

// NewTracker creates a CausalTracker.
func NewTracker(logger *zap.Logger) *Tracker {
	return &Tracker{
		entries: make(map[int32]*entry),
		logger:  logger,
	}
}

// Assign creates a new story_id for the given PID (triggered by rule match).
// If the PID already has a story_id, returns the existing one.
func (t *Tracker) Assign(pid int32) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.entries[pid]; ok {
		// 超过绝对存活上限的 story 就地换新，不等下一轮 Cleanup。
		if time.Since(e.createdAt) < absoluteTTL {
			e.lastSeen = time.Now()
			return e.storyID
		}
		delete(t.entries, pid)
	}

	now := time.Now()
	sid := generateStoryID()
	t.entries[pid] = &entry{storyID: sid, lastSeen: now, createdAt: now}
	return sid
}

// Inherit propagates story_id from parent PID to child PID.
// Called on process_exec events. Returns the inherited story_id or empty string.
func (t *Tracker) Inherit(ppid, pid int32) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	parent, ok := t.entries[ppid]
	if !ok {
		return ""
	}
	now := time.Now()
	parent.lastSeen = now

	// Child inherits parent's story_id AND its creation time —— 绝对 TTL 必须跟着
	// 故事走，否则父进程不停 fork 子进程就能靠"新条目"把同一个 story_id 续期到天荒地老。
	t.entries[pid] = &entry{storyID: parent.storyID, lastSeen: now, createdAt: parent.createdAt}
	return parent.storyID
}

// Lookup returns the story_id for a PID, or empty string if not tracked.
func (t *Tracker) Lookup(pid int32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	e, ok := t.entries[pid]
	if !ok {
		return ""
	}
	return e.storyID
}

// LookupStr converts string PID to int32 and looks up story_id.
func (t *Tracker) LookupStr(pidStr string) string {
	pid, err := strconv.ParseInt(pidStr, 10, 32)
	if err != nil {
		return ""
	}
	return t.Lookup(int32(pid))
}

// Remove removes a PID from tracking (called on process_exit).
// Does NOT immediately remove — keeps entry for entryTTL for late-arriving events.
func (t *Tracker) Remove(pid int32) {
	// No-op: rely on Cleanup() TTL instead of immediate removal.
	// Exit events may arrive before related file/network events.
}

// Cleanup removes stale entries older than entryTTL.
func (t *Tracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	idleCutoff := now.Add(-entryTTL)
	bornCutoff := now.Add(-absoluteTTL)
	for pid, e := range t.entries {
		// 两条独立判据：静默太久，或存在太久。后者不受活跃度续期影响。
		if e.lastSeen.Before(idleCutoff) || e.createdAt.Before(bornCutoff) {
			delete(t.entries, pid)
		}
	}

	// Hard cap: if still over maxEntries, evict oldest.
	if len(t.entries) > maxEntries {
		type pidTime struct {
			pid      int32
			lastSeen time.Time
		}
		all := make([]pidTime, 0, len(t.entries))
		for pid, e := range t.entries {
			all = append(all, pidTime{pid, e.lastSeen})
		}
		// Sort by lastSeen ascending (oldest first) — simple selection of oldest half.
		target := len(t.entries) - maxEntries
		for i := 0; i < target; i++ {
			oldest := i
			for j := i + 1; j < len(all); j++ {
				if all[j].lastSeen.Before(all[oldest].lastSeen) {
					oldest = j
				}
			}
			all[i], all[oldest] = all[oldest], all[i]
			delete(t.entries, all[i].pid)
		}
	}
}

// Stats returns the number of tracked PIDs and unique story_ids.
func (t *Tracker) Stats() (pids, stories int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, e := range t.entries {
		seen[e.storyID] = struct{}{}
	}
	return len(t.entries), len(seen)
}

// generateStoryID creates a random 16-byte hex string (32 chars).
func generateStoryID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
