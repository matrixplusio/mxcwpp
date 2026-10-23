//go:build !linux

package memfd

import (
	"context"
	"sync"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// Scanner is a no-op stub on non-Linux platforms.
type Scanner struct{}

// NewScanner returns nil on non-Linux (memory threat scanning disabled).
func NewScanner(_ *zap.Logger, _ chan<- *event.Event) *Scanner {
	return nil
}

// Start is a no-op stub.
func (s *Scanner) Start(_ context.Context, _ *sync.WaitGroup) {}

// Stats returns zero counters.
func (s *Scanner) Stats() (scans, threats uint64) { return 0, 0 }
