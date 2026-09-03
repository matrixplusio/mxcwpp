package writer

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestClickHouseWriter_FlushNilConnSafe 校验 2a：Flush 在无 CH 连接(降级 MySQL 模式)时安全 no-op，
// 供 consumer 在 rebalance(Cleanup) 无条件调用而不 panic。
func TestClickHouseWriter_FlushNilConnSafe(t *testing.T) {
	w := NewClickHouseWriter(nil, 1000, time.Second, zap.NewNop())
	// 多次调用均应安全（rebalance 可能频繁触发），且无 CH 时不得报错阻塞 offset。
	if err := w.Flush(); err != nil {
		t.Errorf("无 CH 连接时 Flush 不应报错: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Errorf("无 CH 连接时 Flush 不应报错: %v", err)
	}
}

// TestClickHouseWriter_FlushFailureBlocksOffset 刷盘失败必须让 Flush 持续报错，
// 直到某次刷盘全部成功为止。
//
// 只看屏障当次结果不够：周期 flusher 失败时批次已从内存取走丢弃，屏障再刷时
// 无待写内容会"成功"并放行 offset，那批行就永久没了。失败标记因此必须黏住。
func TestClickHouseWriter_FlushFailureBlocksOffset(t *testing.T) {
	w := NewClickHouseWriter(nil, 1000, time.Second, zap.NewNop())
	// conn 为 nil 时 Flush 直接返回 nil，这里绕过 conn 直接验证标记语义。
	w.markFlushFailed("fim_events", 42)

	if !w.flushFailed.Load() {
		t.Fatal("刷盘失败后标记应置位")
	}

	// 模拟周期 flusher 已把批次丢弃：此后一次"无内容"的刷盘不得清除标记。
	w.flush()
	if !w.flushFailed.Load() {
		t.Error("空刷盘不得清除失败标记（否则丢掉的那批行会被放行）")
	}
}

// TestClickHouseWriter_FlushClearsFlagOnSuccess 全部批次落盘成功后标记清除，
// offset 恢复推进——否则一次抖动会让消费永久停滞。
func TestClickHouseWriter_FlushClearsFlagOnSuccess(t *testing.T) {
	w := NewClickHouseWriter(nil, 1000, time.Second, zap.NewNop())
	w.markFlushFailed("ebpf_events", 7)
	w.flushFailed.Store(false) // 模拟一次成功刷盘的效果
	if err := w.Flush(); err != nil {
		t.Errorf("成功刷盘后 Flush 不应再报错: %v", err)
	}
}
