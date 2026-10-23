package leader

import (
	"testing"
	"time"
)

func TestNewElection_DefaultsApplied(t *testing.T) {
	t.Parallel()
	e := NewElection(nil, "i-1", Config{}, nil)
	if e.key != DefaultKey {
		t.Errorf("expected default key, got %s", e.key)
	}
	if e.ttl != DefaultTTL {
		t.Errorf("expected default ttl, got %s", e.ttl)
	}
	if e.renewTick != DefaultRenewTick {
		t.Errorf("expected default renew tick, got %s", e.renewTick)
	}
}

func TestNewElection_CustomConfig(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Key:       "custom:key",
		TTL:       10 * time.Minute,
		RenewTick: 2 * time.Minute,
	}
	e := NewElection(nil, "i-2", cfg, nil)
	if e.key != cfg.Key {
		t.Errorf("expected %s, got %s", cfg.Key, e.key)
	}
	if e.ttl != cfg.TTL {
		t.Errorf("expected %s, got %s", cfg.TTL, e.ttl)
	}
}

func TestIsLeader_DefaultFalse(t *testing.T) {
	t.Parallel()
	e := NewElection(nil, "i-3", Config{}, nil)
	if e.IsLeader() {
		t.Fatal("expected isLeader=false at construct")
	}
}
