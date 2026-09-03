package writer

import (
	"context"
	"errors"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

// 注入真实的 ClickHouse 故障，验证刷盘失败后 Flush 会报错。
//
// 已有的用例直接置 flushFailed 标志再看 Flush 的返回值，测的是标志与返回值的
// 对应关系。这里换成让写入这条路径真的失败——PrepareBatch 返回错误，
// 走完整个 flush 流程——因为验收要问的是「ClickHouse 出故障时 offset 会不会
// 被推进」，而不是「标志位读写是否正确」。
//
// offset 不推进意味着这批消息会被重投、ClickHouse 里可能多出重复行。
// 那是刻意的取舍：归档多几行，远好过安全事件凭空消失且无人知晓。

// failingConn 是 PrepareBatch 必然失败的 ClickHouse 连接。
type failingConn struct {
	chdriver.Conn
	calls int
}

func (c *failingConn) PrepareBatch(context.Context, string, ...chdriver.PrepareBatchOption) (chdriver.Batch, error) {
	c.calls++
	return nil, errors.New("injected: clickhouse unreachable")
}

// Exec 供构造期 ensureSchemas 使用；建表在故障注入的范围之外，返回成功即可。
func (c *failingConn) Exec(context.Context, string, ...any) error { return nil }
func (c *failingConn) Ping(context.Context) error                 { return nil }
func (c *failingConn) Close() error                               { return nil }

func TestFlush_RealFailureBlocksOffset(t *testing.T) {
	conn := &failingConn{}
	w := NewClickHouseWriter(conn, 1000, time.Second, zap.NewNop())

	// 灌入一批待刷盘的数据
	for range 3 {
		if err := w.WriteHostMetrics(&kafka.MQMessage{
			AgentID: "agent-1", DataType: 1000,
		}); err != nil {
			t.Fatalf("WriteHostMetrics: %v", err)
		}
	}

	err := w.Flush()
	if err == nil {
		t.Fatal("ClickHouse 写入失败时 Flush 必须报错——" +
			"返回 nil 会让调用方提交 offset，宣布这些消息已安全落盘，而实际并没有")
	}
	if conn.calls == 0 {
		t.Fatal("测试没有真的走到写入路径，故障注入无效")
	}
	t.Logf("注入生效：PrepareBatch 被调用 %d 次，Flush 返回 %v", conn.calls, err)
}

// 故障期间反复 Flush 必须持续报错，而不是第二次就"恢复"。
//
// 失败标志是粘性的：只有真正成功刷盘的那一轮才清除。若中途自行清零，
// 一次瞬时故障后的下一次 Flush 会返回成功，offset 随即跳过那批从未落盘的消息。
func TestFlush_FailureIsSticky(t *testing.T) {
	conn := &failingConn{}
	w := NewClickHouseWriter(conn, 1000, time.Second, zap.NewNop())

	for range 2 {
		_ = w.WriteHostMetrics(&kafka.MQMessage{AgentID: "a", DataType: 1000})
	}

	for i := range 3 {
		if err := w.Flush(); err == nil {
			t.Fatalf("第 %d 次 Flush 返回 nil——故障仍在，不该报告成功", i+1)
		}
	}
}

// 没有待刷盘数据时不应报错。
//
// 空批次一律报错会让提交屏障永远无法推进 offset：ClickHouse 完全正常，
// 只是这一轮没有数据，而 lag 会一直涨。
func TestFlush_EmptyBatchIsNotAFailure(t *testing.T) {
	conn := &failingConn{}
	w := NewClickHouseWriter(conn, 1000, time.Second, zap.NewNop())

	if err := w.Flush(); err != nil {
		t.Fatalf("无待刷盘数据时不该报错，实际: %v", err)
	}
	if conn.calls != 0 {
		t.Fatalf("空批次不该触发写入，实际调用 %d 次", conn.calls)
	}
}
