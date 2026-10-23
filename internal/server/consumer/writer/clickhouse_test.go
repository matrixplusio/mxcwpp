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
