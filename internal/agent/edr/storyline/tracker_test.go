package storyline

import (
	"testing"
	"time"
)

func TestAssignAndLookup(t *testing.T) {
	tr := NewTracker(nil)

	sid := tr.Assign(1234)
	if sid == "" {
		t.Fatal("Assign should return non-empty story_id")
	}
	if len(sid) != 32 {
		t.Errorf("story_id should be 32 hex chars, got %d", len(sid))
	}

	// Same PID should return same story_id.
	sid2 := tr.Assign(1234)
	if sid2 != sid {
		t.Errorf("duplicate Assign should return same story_id: got %s vs %s", sid2, sid)
	}

	// Lookup should find it.
	if got := tr.Lookup(1234); got != sid {
		t.Errorf("Lookup got %s, want %s", got, sid)
	}

	// Unknown PID returns empty.
	if got := tr.Lookup(9999); got != "" {
		t.Errorf("Lookup unknown PID should be empty, got %s", got)
	}
}

func TestInherit(t *testing.T) {
	tr := NewTracker(nil)

	parentSID := tr.Assign(100)

	// Child inherits parent's story_id.
	childSID := tr.Inherit(100, 200)
	if childSID != parentSID {
		t.Errorf("child should inherit parent story_id: got %s, want %s", childSID, parentSID)
	}

	// Grandchild inherits too.
	grandSID := tr.Inherit(200, 300)
	if grandSID != parentSID {
		t.Errorf("grandchild should inherit: got %s, want %s", grandSID, parentSID)
	}

	// Non-tracked parent returns empty.
	if sid := tr.Inherit(999, 400); sid != "" {
		t.Errorf("inherit from unknown parent should be empty, got %s", sid)
	}
}

func TestLookupStr(t *testing.T) {
	tr := NewTracker(nil)
	tr.Assign(42)

	if sid := tr.LookupStr("42"); sid == "" {
		t.Error("LookupStr should find PID 42")
	}
	if sid := tr.LookupStr("invalid"); sid != "" {
		t.Error("LookupStr invalid should return empty")
	}
}

func TestCleanup(t *testing.T) {
	tr := NewTracker(nil)

	tr.Assign(1)
	tr.Assign(2)

	// Force entries to be stale.
	tr.mu.Lock()
	for _, e := range tr.entries {
		e.lastSeen = time.Now().Add(-3 * time.Hour)
	}
	tr.mu.Unlock()

	tr.Cleanup()

	if pids, _ := tr.Stats(); pids != 0 {
		t.Errorf("stale entries should be cleaned, got %d PIDs", pids)
	}
}

func TestStats(t *testing.T) {
	tr := NewTracker(nil)

	tr.Assign(10)
	tr.Assign(20)
	tr.Inherit(10, 30) // same story as PID 10

	pids, stories := tr.Stats()
	if pids != 3 {
		t.Errorf("expected 3 PIDs, got %d", pids)
	}
	if stories != 2 {
		t.Errorf("expected 2 unique stories, got %d", stories)
	}
}
