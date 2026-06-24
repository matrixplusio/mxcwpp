// Package buffer 提供 Agent 数据传输的环形缓冲区
//
// 参考 Elkeid agent/buffer/buffer.go 设计：
// 固定数组 + mutex + offset，批量读取清空，区分插件数据和内部数据的满溢策略。
package buffer

import (
	"sync"

	"github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

const (
	// BufSize 缓冲区容量（与 Elkeid 一致）
	// 100ms 发送间隔下，理论吞吐上限 20480 条/s
	BufSize = 2048
)

// RingBuffer 是固定大小的环形缓冲区
// 用于在 Agent 内部缓冲 EncodedRecord，由 sendData 定时批量消费
type RingBuffer struct {
	mu     sync.Mutex
	buf    [BufSize]*grpc.EncodedRecord
	offset int

	// 监控指标（原子累加，心跳上报用）
	overflowCount uint64
}

// New 创建新的环形缓冲区
func New() *RingBuffer {
	return &RingBuffer{}
}

// WriteEncodedRecord 写入一条插件数据
// 缓冲区满时丢弃新数据（不阻塞插件进程），返回 false
func (r *RingBuffer) WriteEncodedRecord(rec *grpc.EncodedRecord) bool {
	r.mu.Lock()
	if r.offset < BufSize {
		r.buf[r.offset] = rec
		r.offset++
		r.mu.Unlock()
		return true
	}
	// 缓冲区满，丢弃新数据
	r.overflowCount++
	r.mu.Unlock()
	return false
}

// WriteRecord 写入一条内部数据（心跳等）
// 缓冲区满时覆盖 buf[0]（最新心跳比最旧数据更有价值）
func (r *RingBuffer) WriteRecord(rec *grpc.EncodedRecord) {
	r.mu.Lock()
	if r.offset < BufSize {
		r.buf[r.offset] = rec
		r.offset++
	} else {
		// 缓冲区满，覆盖最旧数据（与 Elkeid WriteRecord 行为一致）
		r.buf[0] = rec
		r.overflowCount++
	}
	r.mu.Unlock()
}

// ReadAll 批量读取所有缓冲数据并清空
// 返回的切片是数据的拷贝，调用方可安全使用
func (r *RingBuffer) ReadAll() []*grpc.EncodedRecord {
	r.mu.Lock()
	if r.offset == 0 {
		r.mu.Unlock()
		return nil
	}
	ret := make([]*grpc.EncodedRecord, r.offset)
	copy(ret, r.buf[:r.offset])
	// 清空指针引用，帮助 GC
	for i := 0; i < r.offset; i++ {
		r.buf[i] = nil
	}
	r.offset = 0
	r.mu.Unlock()
	return ret
}

// Clear 清空缓冲区（连接断开时使用）
func (r *RingBuffer) Clear() {
	r.mu.Lock()
	for i := 0; i < r.offset; i++ {
		r.buf[i] = nil
	}
	r.offset = 0
	r.mu.Unlock()
}

// Len 返回当前缓冲数据条数
func (r *RingBuffer) Len() int {
	r.mu.Lock()
	n := r.offset
	r.mu.Unlock()
	return n
}

// OverflowCount 返回累计满溢丢弃次数（用于监控指标上报）
func (r *RingBuffer) OverflowCount() uint64 {
	r.mu.Lock()
	n := r.overflowCount
	r.mu.Unlock()
	return n
}

// ResetOverflowCount 重置满溢计数（上报后清零）
func (r *RingBuffer) ResetOverflowCount() uint64 {
	r.mu.Lock()
	n := r.overflowCount
	r.overflowCount = 0
	r.mu.Unlock()
	return n
}
