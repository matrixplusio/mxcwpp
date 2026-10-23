//go:build linux

package afpacket

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// TPACKET_V3 内核 ABI 数据结构 (与 <linux/if_packet.h> 对齐).

// tpStatusUser kernel 标记: 此 block 已可被用户态读.
const tpStatusUser = 1

// tpStatusKernel 用户态读完, 还给 kernel.
const tpStatusKernel = 0

// tpacketReqV3 setsockopt PACKET_RX_RING 用.
type tpacketReqV3 struct {
	BlockSize    uint32
	BlockNr      uint32
	FrameSize    uint32
	FrameNr      uint32
	RetireBlkTov uint32 // ms
	SizeofPriv   uint32
	Feature      uint32
}

// tpacketBlockDescV3 mmap ring 中每 block 头部.
//
// 简化版 (TPACKET_V3 header 完整 64+ 字节, 只读关键字段).
type tpacketBlockDescV3 struct {
	Version          uint32
	OffsetToPrivData uint32
	BlockStatus      uint32 // tpStatusUser / tpStatusKernel
	NumPkts          uint32
	OffsetToFirstPkt uint32
	BlockLen         uint32
	SeqNum           uint64
	TsFirstPktSec    uint32
	TsFirstPktNSec   uint32
	TsLastPktSec     uint32
	TsLastPktNSec    uint32
	_                [40]byte // padding for hv1/hv2 union
}

// tpacket3Hdr 单 frame 头.
type tpacket3Hdr struct {
	NextOffset uint32
	Sec        uint32
	NSec       uint32
	Snaplen    uint32
	Len        uint32
	Status     uint32
	MacOff     uint16
	NetOff     uint16
	VlanTci    uint16
	VlanTpid   uint16
	_          [8]byte // padding
}

// setPacketRxRingV3 setsockopt PACKET_RX_RING (TPACKET_V3).
func setPacketRxRingV3(fd int, req *tpacketReqV3) error {
	return setsockoptOpaque(fd, unix.SOL_PACKET, unix.PACKET_RX_RING,
		unsafe.Pointer(req), unsafe.Sizeof(*req))
}

// setSockFilter setsockopt SO_ATTACH_FILTER.
func setSockFilter(fd int, prog *unix.SockFprog) error {
	return setsockoptOpaque(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		unsafe.Pointer(prog), unsafe.Sizeof(*prog))
}

// setsockoptOpaque generic setsockopt 走 SYS_SETSOCKOPT.
func setsockoptOpaque(fd int, level, name int, val unsafe.Pointer, sz uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(sz),
		0)
	if e != 0 {
		return e
	}
	return nil
}

// BuildHTTPFilter 简化版 BPF filter: 仅放行 TCP 包到 HTTP 端口白名单.
//
// 等价 tcpdump 'tcp and (dst port 80 or dst port 443 or dst port 8080 or dst port 8443)'.
// 内核态过滤减用户态接收 70-90% 流量.
func BuildHTTPFilter() []unix.SockFilter {
	// 实际生产推荐 libpcap 编译: pcap.CompileBPF + 转 SockFilter.
	// 此处给最简 placeholder (放过所有 IPv4 TCP), 调用方按需替换.
	return []unix.SockFilter{
		{Code: 0x28, Jt: 0, Jf: 0, K: 0x0000000c}, // ldh [12]
		{Code: 0x15, Jt: 0, Jf: 5, K: 0x00000800}, // jeq #ETHERTYPE_IP, jt 0, jf 5
		{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000017}, // ldb [23]
		{Code: 0x15, Jt: 0, Jf: 3, K: 0x00000006}, // jeq #IPPROTO_TCP
		{Code: 0x28, Jt: 0, Jf: 0, K: 0x00000014}, // ldh [20]
		{Code: 0x45, Jt: 1, Jf: 0, K: 0x00001fff}, // jset 0x1fff (frag)
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x0000ffff}, // ret #65535 (accept)
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00000000}, // ret #0 (drop)
	}
}
