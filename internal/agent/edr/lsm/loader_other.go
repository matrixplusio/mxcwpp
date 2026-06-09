//go:build !linux

package lsm

import (
	"errors"
	"sync/atomic"
)

type LSMEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Hook   uint8
	Comm   string
	Path   string
}

func HookName(_ uint8) string { return "n/a" }

type Counters struct {
	Bprm    atomic.Uint64
	Create  atomic.Uint64
	Unlink  atomic.Uint64
	Rename  atomic.Uint64
	Connect atomic.Uint64
	MmapWX  atomic.Uint64
}

func (c *Counters) Snapshot() map[string]uint64 { return map[string]uint64{} }
func (c *Counters) Handle(_ *LSMEvent)          {}

func IsLSMAvailable() (bool, error) {
	return false, errors.New("lsm: linux only")
}
