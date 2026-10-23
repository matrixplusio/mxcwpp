//go:build linux

// Package afpacket — AF_PACKET v3 (TPACKET_V3) mmap ring buffer reader (P3-K').
//
// 给 CentOS 7 默认 kernel 3.10 用 (cgroup_skb 不支持). TPACKET_V3 自 kernel 3.2 起,
// 性能 80% DPDK, 用户态零拷贝 ring buffer 读包.
//
// 用法:
//
//	r, err := afpacket.NewReader(afpacket.Config{
//	    Interface:  "eth0",
//	    BlockSize:  1 << 20, // 1MB
//	    NumBlocks:  64,
//	    Filter:     bpfHTTP(),
//	})
//	if err != nil { ... }
//	defer r.Close()
//	for pkt := range r.Packets() {
//	    if isAttack(pkt.Data) { reportAlert(pkt) }
//	}
package afpacket

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Config reader 配置.
type Config struct {
	Interface string            // 网卡名 (e.g. eth0)
	BlockSize int               // 单 block 大小 (默认 1MB), 必须 page-size 对齐
	NumBlocks int               // block 数量 (默认 64), 总 ring = BlockSize × NumBlocks
	FrameSize int               // 单 frame 大小 (默认 2048 = MTU+headroom)
	Timeout   time.Duration     // block 超时 (默认 10ms)
	Promisc   bool              // 混杂模式 (大流量审计场景需开)
	Filter    []unix.SockFilter // BPF socket filter (可选, 内核态过滤减用户态开销)
}

// Packet 单包.
type Packet struct {
	Data      []byte
	Timestamp time.Time
	IfaceIdx  int
	Protocol  uint16
	Truncated bool
}

// Reader AF_PACKET v3 reader.
type Reader struct {
	fd          int
	ring        []byte
	cfg         Config
	packets     chan Packet
	stopOnce    sync.Once
	stopCh      chan struct{}
	pktsRead    atomic.Uint64
	pktsDropped atomic.Uint64
}

// NewReader 构造 + 启动后台读循环.
func NewReader(cfg Config) (*Reader, error) {
	if cfg.Interface == "" {
		return nil, errors.New("afpacket: interface required")
	}
	if cfg.BlockSize == 0 {
		cfg.BlockSize = 1 << 20
	}
	if cfg.NumBlocks == 0 {
		cfg.NumBlocks = 64
	}
	if cfg.FrameSize == 0 {
		cfg.FrameSize = 2048
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Millisecond
	}

	// 1. 创建 PF_PACKET / SOCK_RAW socket (ETH_P_ALL = 0x0003 网络字节序 = 0x0300)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	r := &Reader{
		fd:      fd,
		cfg:     cfg,
		packets: make(chan Packet, 1024),
		stopCh:  make(chan struct{}),
	}

	// 2. SO_RCVTIMEO 防 recvfrom 永久阻塞
	tv := unix.NsecToTimeval(int64(cfg.Timeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// 3. PACKET_VERSION = TPACKET_V3
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set TPACKET_V3: %w", err)
	}

	// 4. PACKET_RX_RING (TPACKET_V3 layout)
	req := tpacketReqV3{
		BlockSize:    uint32(cfg.BlockSize),
		BlockNr:      uint32(cfg.NumBlocks),
		FrameSize:    uint32(cfg.FrameSize),
		FrameNr:      uint32(cfg.BlockSize/cfg.FrameSize) * uint32(cfg.NumBlocks),
		RetireBlkTov: uint32(cfg.Timeout / time.Millisecond),
	}
	if err := setPacketRxRingV3(fd, &req); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set rx ring: %w", err)
	}

	// 5. mmap
	totalSize := cfg.BlockSize * cfg.NumBlocks
	ring, err := unix.Mmap(fd, 0, totalSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("mmap: %w", err)
	}
	r.ring = ring

	// 6. 绑定到 interface
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		_ = unix.Munmap(ring)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("InterfaceByName: %w", err)
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Munmap(ring)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	// 7. Promisc 模式 (可选)
	if cfg.Promisc {
		mreq := unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	}

	// 8. BPF socket filter (内核态过滤减用户态开销)
	if len(cfg.Filter) > 0 {
		prog := unix.SockFprog{
			Len:    uint16(len(cfg.Filter)),
			Filter: &cfg.Filter[0],
		}
		_ = setSockFilter(fd, &prog)
	}

	// 9. 启动后台读
	go r.run()
	return r, nil
}

// Packets 订阅包流.
func (r *Reader) Packets() <-chan Packet { return r.packets }

// Stats 累计.
func (r *Reader) Stats() (read, dropped uint64) {
	return r.pktsRead.Load(), r.pktsDropped.Load()
}

// Close 优雅关闭.
func (r *Reader) Close() error {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
	if r.ring != nil {
		_ = unix.Munmap(r.ring)
		r.ring = nil
	}
	if r.fd > 0 {
		err := unix.Close(r.fd)
		r.fd = -1
		return err
	}
	return nil
}

// run 后台循环读 block.
func (r *Reader) run() {
	defer close(r.packets)
	blockIdx := 0
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		blockOffset := blockIdx * r.cfg.BlockSize
		blockHdr := (*tpacketBlockDescV3)(unsafe.Pointer(&r.ring[blockOffset]))
		// kernel 完成标志
		if blockHdr.BlockStatus&tpStatusUser == 0 {
			// 没新 block, poll 等
			pfd := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
			_, _ = unix.Poll(pfd, int(r.cfg.Timeout/time.Millisecond))
			continue
		}
		// 解析 frames
		r.processBlock(blockOffset, blockHdr)
		// 还回 kernel
		blockHdr.BlockStatus = tpStatusKernel
		blockIdx = (blockIdx + 1) % r.cfg.NumBlocks
	}
}

// processBlock 解析单 block.
func (r *Reader) processBlock(blockOffset int, hdr *tpacketBlockDescV3) {
	frameOff := int(hdr.OffsetToFirstPkt)
	for i := uint32(0); i < hdr.NumPkts; i++ {
		pkt := (*tpacket3Hdr)(unsafe.Pointer(&r.ring[blockOffset+frameOff]))
		if pkt.Snaplen == 0 || pkt.MacOff == 0 {
			break
		}
		dataOff := blockOffset + frameOff + int(pkt.MacOff)
		if dataOff+int(pkt.Snaplen) > len(r.ring) {
			break
		}
		data := make([]byte, pkt.Snaplen)
		copy(data, r.ring[dataOff:dataOff+int(pkt.Snaplen)])

		select {
		case r.packets <- Packet{
			Data:      data,
			Timestamp: time.Unix(int64(pkt.Sec), int64(pkt.NSec)),
			Truncated: pkt.Snaplen < pkt.Len,
		}:
			r.pktsRead.Add(1)
		default:
			r.pktsDropped.Add(1)
		}
		if pkt.NextOffset == 0 {
			break
		}
		frameOff += int(pkt.NextOffset)
	}
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
