//go:build linux

// detector_linux.go — memfd_create→execveat 用户态事件 (C9).
package memfd

import (
	"sync/atomic"
	"time"
)

// FilelessEvent userspace 事件.
type FilelessEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Kind   uint8 // 1=memfd_create, 2=execveat_memfd
	Comm   string
	Name   string
}

// Metrics 累计计数.
type Metrics struct {
	MemfdCreates  atomic.Uint64
	ExecveAtMemfd atomic.Uint64
}

// Snapshot 拷贝 counter.
func (m *Metrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"memfd_creates":  m.MemfdCreates.Load(),
		"execveat_memfd": m.ExecveAtMemfd.Load(),
	}
}

// Handle 处理单事件.
func (m *Metrics) Handle(ev *FilelessEvent) {
	if ev == nil {
		return
	}
	switch ev.Kind {
	case 1:
		m.MemfdCreates.Add(1)
	case 2:
		m.ExecveAtMemfd.Add(1)
	}
}

// AssociationWindow 与 BPF 程序保持一致.
const AssociationWindow = 5 * time.Second
