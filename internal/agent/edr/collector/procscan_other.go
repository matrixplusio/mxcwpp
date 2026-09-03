//go:build !linux

package collector

// Build-tag stubs — these types mirror the Linux implementation in procscan.go.
// On non-Linux, ebpf.go is not compiled, so nothing references these.

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

type procEntry struct { //nolint:unused
	pid, ppid, uid int
	exe, cmdline   string
}

type procScanner struct{} //nolint:unused

func newProcScanner(_ *zap.Logger, _ chan<- *event.Event) *procScanner { return &procScanner{} } //nolint:unused

func (s *procScanner) initialSnapshot() error { return nil } //nolint:unused

func (s *procScanner) reconcileLoop(_ context.Context, wg *sync.WaitGroup, _ time.Duration) { //nolint:unused
	defer wg.Done()
}

func (s *procScanner) addKnown(_ int, _ procEntry) {} //nolint:unused
func (s *procScanner) removeKnown(_ int)           {} //nolint:unused
