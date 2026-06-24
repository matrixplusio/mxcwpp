//go:build !linux

package collector

// Build-tag stubs — these types mirror the Linux implementation in cnproc.go.
// On non-Linux, userspace.go is not compiled, so nothing references these.

import (
	"context"
	"sync"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

type cnProcListener struct{} //nolint:unused

func newCNProcListener(_ *zap.Logger, _ chan<- *event.Event) (*cnProcListener, error) { //nolint:unused
	return nil, nil
}

func (l *cnProcListener) readLoop(_ context.Context, _ *sync.WaitGroup) {} //nolint:unused
func (l *cnProcListener) close()                                        {} //nolint:unused
