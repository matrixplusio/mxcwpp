//go:build !linux

package memfd

import (
	"sync/atomic"
	"time"
)

type FilelessEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Kind   uint8
	Comm   string
	Name   string
}

type Metrics struct {
	MemfdCreates  atomic.Uint64
	ExecveAtMemfd atomic.Uint64
}

func (m *Metrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"memfd_creates":  m.MemfdCreates.Load(),
		"execveat_memfd": m.ExecveAtMemfd.Load(),
	}
}

func (m *Metrics) Handle(_ *FilelessEvent) {}

const AssociationWindow = 5 * time.Second
