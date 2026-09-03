//go:build linux

// dirtypipe_pwnkit_linux.go — Userspace loader / event consumer for DirtyPipe + PwnKit eBPF probes (P4-9).
//
// 配套 bpf/dirtypipe.c 与 bpf/pwnkit.c 用户态.
// 走 cilium/ebpf 自动 build embed (CGO=0); 这里只放骨架, 真实加载逻辑在 npatch.Manager 里.
package npatch

import (
	"context"
	"sync/atomic"
	"time"
)

// DirtyPipeEvent userspace 解码后的事件.
type DirtyPipeEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Kind   uint8 // 1=splice, 2=suspicious_write
	Comm   string
}

// PwnKitEvent userspace 解码后的事件.
type PwnKitEvent struct {
	TimeNS   uint64
	PID      uint32
	UID      uint32
	PPID     uint32
	Comm     string
	Filename string
}

// VirtualPatchMetrics 给 manager UI 看的累计计数.
type VirtualPatchMetrics struct {
	DirtyPipeSplice   atomic.Uint64
	DirtyPipeSuspect  atomic.Uint64
	PwnKitInvocations atomic.Uint64
}

// Snapshot 拷贝 counter (无锁).
func (m *VirtualPatchMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"dirtypipe_splice":   m.DirtyPipeSplice.Load(),
		"dirtypipe_suspect":  m.DirtyPipeSuspect.Load(),
		"pwnkit_invocations": m.PwnKitInvocations.Load(),
	}
}

// HandleDirtyPipe 处理一条 ringbuf 事件 (read-only).
//
// observe-only: 仅累计 + 上报 alert, 不阻塞 syscall.
func (m *VirtualPatchMetrics) HandleDirtyPipe(ctx context.Context, ev *DirtyPipeEvent) {
	if ev == nil {
		return
	}
	switch ev.Kind {
	case 1:
		m.DirtyPipeSplice.Add(1)
	case 2:
		m.DirtyPipeSuspect.Add(1)
	}
}

// HandlePwnKit 处理一条 pkexec exec 事件.
func (m *VirtualPatchMetrics) HandlePwnKit(ctx context.Context, ev *PwnKitEvent) {
	if ev == nil {
		return
	}
	m.PwnKitInvocations.Add(1)
}

// SuspiciousWindow 关联 splice → write 的时间窗口 (与 BPF 程序保持一致).
const SuspiciousWindow = 5 * time.Second
