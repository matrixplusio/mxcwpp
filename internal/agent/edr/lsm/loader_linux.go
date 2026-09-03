//go:build linux

// loader_linux.go — BPF LSM 用户态 (C10 骨架).
//
// 加载 lsm_hooks.bpf.o 需 cilium/ebpf + bpf2go. 当前仅给 userspace 事件类型 + 计数.
package lsm

import (
	"errors"
	"sync/atomic"
)

// LSMEvent userspace 事件.
type LSMEvent struct {
	TimeNS uint64
	PID    uint32
	UID    uint32
	Hook   uint8 // 1=bprm 2=create 3=unlink 4=rename 5=connect 6=mmap
	Comm   string
	Path   string
}

// HookName 转可读名.
func HookName(h uint8) string {
	switch h {
	case 1:
		return "bprm_check_security"
	case 2:
		return "inode_create"
	case 3:
		return "inode_unlink"
	case 4:
		return "inode_rename"
	case 5:
		return "socket_connect"
	case 6:
		return "mmap_file_wx"
	}
	return "unknown"
}

// Counters 累计计数.
type Counters struct {
	Bprm    atomic.Uint64
	Create  atomic.Uint64
	Unlink  atomic.Uint64
	Rename  atomic.Uint64
	Connect atomic.Uint64
	MmapWX  atomic.Uint64
}

// Snapshot 拷.
func (c *Counters) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"bprm":    c.Bprm.Load(),
		"create":  c.Create.Load(),
		"unlink":  c.Unlink.Load(),
		"rename":  c.Rename.Load(),
		"connect": c.Connect.Load(),
		"mmap_wx": c.MmapWX.Load(),
	}
}

// Handle 单事件计数 + 上报回调钩子.
func (c *Counters) Handle(ev *LSMEvent) {
	if ev == nil {
		return
	}
	switch ev.Hook {
	case 1:
		c.Bprm.Add(1)
	case 2:
		c.Create.Add(1)
	case 3:
		c.Unlink.Add(1)
	case 4:
		c.Rename.Add(1)
	case 5:
		c.Connect.Add(1)
	case 6:
		c.MmapWX.Add(1)
	}
}

// IsLSMAvailable 检测内核是否支持 BPF LSM.
//
// 需 kernel 5.7+ + CONFIG_BPF_LSM=y + lsm= 启动参数含 bpf.
func IsLSMAvailable() (bool, error) {
	// 读 /sys/kernel/security/lsm, 含 "bpf" 即支持
	data, err := readFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, err
	}
	if !containsBytes(data, []byte("bpf")) {
		return false, errors.New("BPF LSM not in active lsm chain")
	}
	return true, nil
}
