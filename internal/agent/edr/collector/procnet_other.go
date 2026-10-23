//go:build !linux

package collector

// Build-tag stubs — these types mirror the Linux implementation in procnet.go.
// On non-Linux, userspace.go is not compiled, so nothing references these.

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

type procNetPoller struct{} //nolint:unused

func newProcNetPoller(_ *zap.Logger, _ chan<- *event.Event, _ time.Duration) *procNetPoller { //nolint:unused
	return &procNetPoller{}
}

func (p *procNetPoller) pollLoop(_ context.Context, _ *sync.WaitGroup) {} //nolint:unused
