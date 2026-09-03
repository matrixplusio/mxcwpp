// Package probe — kernel 特性探测 (P3-K').
//
// NPatch 双路径: kernel 4.10+ 走 cgroup_skb eBPF, 老内核 (CentOS 7 默认 3.10) 走 AF_PACKET v3.
//
// 实测兼容矩阵:
//
//	CentOS 7 / RHEL 7 / Oracle Linux 7 RHCK (kernel 3.10):
//	  AF_PACKET v3 ✅ + cgroup_skb ❌ → 用 AF_PACKET v3 fallback
//
//	CentOS 7 + ELRepo kernel-ml 5.x / Oracle Linux 7 UEK 5.4:
//	  AF_PACKET v3 ✅ + cgroup_skb ✅ → 优先 cgroup_skb
//
//	CentOS/Rocky/RHEL 8+ / Ubuntu 22.04+ / Debian 11+:
//	  AF_PACKET v3 ✅ + cgroup_skb ✅ → 用 cgroup_skb (in-kernel 高效)
package probe

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
)

// KernelVersion (major, minor, patch).
type KernelVersion struct {
	Major, Minor, Patch int
	Raw                 string
}

// AtLeast 大于等于指定版本.
func (kv KernelVersion) AtLeast(major, minor int) bool {
	if kv.Major != major {
		return kv.Major > major
	}
	return kv.Minor >= minor
}

// String 还原.
func (kv KernelVersion) String() string { return kv.Raw }

var (
	once     sync.Once
	cached   KernelVersion
	cacheErr error
)

// Kernel 取当前内核版本 (cache, 一次性).
func Kernel() (KernelVersion, error) {
	once.Do(func() {
		cached, cacheErr = readKernelVersion()
	})
	return cached, cacheErr
}

// readKernelVersion 读 /proc/sys/kernel/osrelease.
//
// 格式: "3.10.0-1160.el7.x86_64" / "5.15.0-72-generic" / "6.1.0-13-amd64"
func readKernelVersion() (KernelVersion, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return KernelVersion{}, err
	}
	raw := strings.TrimSpace(string(data))
	// 切到非 [0-9.] 字符为止
	cut := raw
	for i, c := range raw {
		if !((c >= '0' && c <= '9') || c == '.') {
			cut = raw[:i]
			break
		}
	}
	parts := strings.Split(cut, ".")
	kv := KernelVersion{Raw: raw}
	if len(parts) > 0 {
		kv.Major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		kv.Minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		kv.Patch, _ = strconv.Atoi(parts[2])
	}
	return kv, nil
}

// Backend NPatch 路径选择.
type Backend string

const (
	// BackendCgroupSkb kernel 4.10+ in-kernel eBPF (最优).
	BackendCgroupSkb Backend = "cgroup_skb"
	// BackendAFPacket kernel 3.10+ AF_PACKET v3 用户态 7 层 (兼容 CentOS 7).
	BackendAFPacket Backend = "af_packet_v3"
	// BackendUnsupported 内核太老或缺少 socket 能力.
	BackendUnsupported Backend = "unsupported"
)

// SelectBackend 自动选择 NPatch 路径.
func SelectBackend() (Backend, error) {
	kv, err := Kernel()
	if err != nil {
		return BackendUnsupported, err
	}
	// kernel 4.10+ 才有完整 BPF_PROG_TYPE_CGROUP_SKB
	if kv.AtLeast(4, 10) {
		return BackendCgroupSkb, nil
	}
	// kernel 3.2+ 才有 TPACKET_V3 (CentOS 7 默认 3.10 满足)
	if kv.AtLeast(3, 2) {
		return BackendAFPacket, nil
	}
	return BackendUnsupported, nil
}

// IsCentOS7Default 启发式探测是否 CentOS 7 默认内核 (el7 后缀).
//
// 给运维报告 hint: "您当前 CentOS 7 默认内核, NPatch 走 AF_PACKET 兼容路径. 推荐升级 ELRepo kernel-ml 5.15 启用 eBPF 高效路径."
func IsCentOS7Default() bool {
	kv, _ := Kernel()
	return bytes.Contains([]byte(kv.Raw), []byte(".el7."))
}
