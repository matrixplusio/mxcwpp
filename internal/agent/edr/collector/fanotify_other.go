//go:build !linux

package collector

// Build-tag stubs — these types mirror the Linux implementation in fanotify.go.
// On non-Linux, userspace.go is not compiled, so nothing references these.

import (
	"context"
	"sync"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

type fanotifyListener struct{} //nolint:unused

func newFanotifyListener(_ *zap.Logger, _ chan<- *event.Event) (*fanotifyListener, error) { //nolint:unused
	return nil, nil
}

func (l *fanotifyListener) readLoop(_ context.Context, _ *sync.WaitGroup) {} //nolint:unused
func (l *fanotifyListener) close()                                        {} //nolint:unused
