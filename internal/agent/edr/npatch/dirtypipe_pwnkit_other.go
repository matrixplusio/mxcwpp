//go:build !linux

package npatch

import (
	"context"
	"sync/atomic"
	"time"
)

type DirtyPipeEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Kind   uint8
	Comm   string
}

type PwnKitEvent struct {
	TimeNS   uint64
	PID      uint32
	UID      uint32
	PPID     uint32
	Comm     string
	Filename string
}

type VirtualPatchMetrics struct {
	DirtyPipeSplice   atomic.Uint64
	DirtyPipeSuspect  atomic.Uint64
	PwnKitInvocations atomic.Uint64
}

func (m *VirtualPatchMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"dirtypipe_splice":   m.DirtyPipeSplice.Load(),
		"dirtypipe_suspect":  m.DirtyPipeSuspect.Load(),
		"pwnkit_invocations": m.PwnKitInvocations.Load(),
	}
}

func (m *VirtualPatchMetrics) HandleDirtyPipe(ctx context.Context, ev *DirtyPipeEvent) {}
func (m *VirtualPatchMetrics) HandlePwnKit(ctx context.Context, ev *PwnKitEvent)       {}

const SuspiciousWindow = 5 * time.Second
