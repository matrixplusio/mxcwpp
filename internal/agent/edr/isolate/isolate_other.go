//go:build !linux

package isolate

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Manager is a no-op stub on non-Linux platforms.
type Manager struct{}

// NewManager returns a no-op manager on non-Linux.
func NewManager(_ *zap.Logger, _ string) *Manager { return &Manager{} }

// Isolate is not supported on non-Linux.
func (m *Manager) Isolate(_ string, _ int, _ Level) error {
	return fmt.Errorf("network isolation requires Linux")
}

// Release is a no-op on non-Linux.
func (m *Manager) Release(_ string) error { return nil }

// BlockIP is not supported on non-Linux.
func (m *Manager) BlockIP(_ BlockRule) error {
	return fmt.Errorf("network blocking requires Linux")
}

// UnblockIP is a no-op on non-Linux.
func (m *Manager) UnblockIP(_ uint) error { return nil }

// IsIsolated always returns false on non-Linux.
func (m *Manager) IsIsolated() bool { return false }

// GetLevel returns LevelNone on non-Linux.
func (m *Manager) GetLevel() Level { return LevelNone }

// Status returns empty state on non-Linux.
func (m *Manager) Status() (level Level, reason string, since time.Time, blockCount int) {
	return LevelNone, "", time.Time{}, 0
}

// BlockRules returns nil on non-Linux.
func (m *Manager) BlockRules() []BlockRule { return nil }
