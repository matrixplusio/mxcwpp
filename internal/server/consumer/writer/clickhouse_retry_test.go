package writer

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

func fimRow(id string) fimEventRow {
	return fimEventRow{HostID: id, Severity: "critical", ChangeType: "changed"}
}

// 写失败的行留在内存里重试，恢复后每行恰好写入一次；恢复之前提交屏障不得放行 offset。
func TestFlushKeepsFailedRowsUntilWritten(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 2}
	w := newSendTestWriter(conn)
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b"), fimRow("c")}

	for i := 0; i < 2; i++ {
		if err := w.Flush(); err == nil {
			t.Fatalf("第 %d 次刷盘写失败，Flush 必须报错以阻止 offset 推进", i+1)
		}
		if len(w.fimRows) != 3 {
			t.Fatalf("失败的行必须留在缓冲里，实际剩 %d 行", len(w.fimRows))
		}
	}
	if got := testutil.ToFloat64(consumermetrics.CHRetryRows.WithLabelValues("fim_events")); got != 3 {
		t.Errorf("待重试行数指标应为 3，实际 %v", got)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("ClickHouse 恢复后 Flush 应成功: %v", err)
	}
	if fmt.Sprint(conn.sent) != "[a b c]" {
		t.Errorf("每行应恰好写入一次，实际 %v", conn.sent)
	}
	if got := testutil.ToFloat64(consumermetrics.CHRetryRows.WithLabelValues("fim_events")); got != 0 {
		t.Errorf("写成功后待重试行数应归零，实际 %v", got)
	}
}

// 原来的漏洞：一张表写失败、另一张表写成功，失败标记被清掉，offset 照常提交，
// 失败的那批永久丢失。现在每张表各自记账，任何一张没写进去都不放行。
func TestOtherTableSuccessDoesNotReleaseOffsets(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 1, failOnly: "fim_events"}
	w := newSendTestWriter(conn)
	w.fimRows = []fimEventRow{fimRow("evidence")}
	w.metricRows = []hostMetricRow{{HostID: "m1"}}

	if err := w.Flush(); err == nil {
		t.Fatal("FIM 写失败时，即使 host_metrics 写成功，Flush 也必须报错")
	}
	w.metricRows = append(w.metricRows, hostMetricRow{HostID: "m2"})
	if err := w.Flush(); err != nil {
		t.Fatalf("FIM 恢复后应放行: %v", err)
	}
	found := false
	for _, id := range conn.sent {
		if id == "evidence" {
			found = true
		}
	}
	if !found {
		t.Errorf("失败过的 FIM 行最终必须写入，实际写入 %v", conn.sent)
	}
}

// 重试的行排在新到的行之前，保持先后顺序。
func TestRetriedRowsStayAheadOfNewRows(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 1}
	w := newSendTestWriter(conn)
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b")}
	_ = w.Flush()
	w.fimRows = append(w.fimRows, fimRow("c"))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(conn.sent) != "[a b c]" {
		t.Errorf("顺序应为 a b c，实际 %v", conn.sent)
	}
}

// 写失败时被拒收（取值不合表结构）的行不放回缓冲：它们重试多少次也写不进去。
func TestRejectedRowsAreNotRetried(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 1}
	w := newSendTestWriter(conn)
	w.fimRows = []fimEventRow{fimRow("good"), {HostID: "bad", Severity: "bogus", ChangeType: "changed"}}
	_ = w.Flush()
	if len(w.fimRows) != 1 || w.fimRows[0].HostID != "good" {
		t.Fatalf("只应放回没被拒收的行，实际 %+v", w.fimRows)
	}
}

// 缓冲超过上限时写入方等待，刷盘腾出空间后放行。
func TestBackpressureBlocksUntilFlushMakesRoom(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}}
	w := newSendTestWriter(conn)
	w.maxBuffered = 2
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b")}

	done := make(chan struct{})
	go func() {
		_ = w.WriteFIMEvent(&kafka.MQMessage{AgentID: "c"})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("缓冲已满时写入方应等待")
	case <-time.After(100 * time.Millisecond):
	}
	w.flush()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("刷盘腾出空间后写入方应被放行")
	}
}

// 等待有上限：停机与重平衡要等消息处理返回，不能无限阻塞。超时照常追加并计数。
func TestBackpressureWaitIsBounded(t *testing.T) {
	old := backpressureWait
	backpressureWait = 50 * time.Millisecond
	defer func() { backpressureWait = old }()

	w := newSendTestWriter(&fakeConn{bad: map[string]bool{}})
	w.maxBuffered = 1
	w.fimRows = []fimEventRow{fimRow("a")}
	before := testutil.ToFloat64(consumermetrics.CHBackpressureTimeoutsTotal)

	start := time.Now()
	_ = w.WriteFIMEvent(&kafka.MQMessage{AgentID: "b"})
	if time.Since(start) > 2*time.Second {
		t.Fatal("等待超时后应放行")
	}
	if len(w.fimRows) != 2 {
		t.Errorf("超时后应照常追加，实际 %d 行", len(w.fimRows))
	}
	if testutil.ToFloat64(consumermetrics.CHBackpressureTimeoutsTotal)-before != 1 {
		t.Error("等待超时应计数")
	}
}

// 并发写入、周期刷盘与提交屏障同时进行，ClickHouse 间歇失败：最终零丢失、零重复。
func TestConcurrentWritesWithFlappingClickHouse(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failEvery: 3}
	w := newSendTestWriter(conn)
	w.batchSize = 50

	const writers, perWriter = 8, 500
	var wg sync.WaitGroup
	stop := make(chan struct{})
	flusherDone := make(chan struct{})
	go func() {
		defer close(flusherDone)
		for {
			select {
			case <-stop:
				return
			default:
				w.flush()
				_ = w.Flush()
			}
		}
	}()
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_ = w.WriteEBPFEvent(&kafka.MQMessage{AgentID: fmt.Sprintf("%d-%d", g, i)})
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	<-flusherDone

	conn.failEvery = 0
	deadline := time.Now().Add(5 * time.Second)
	for w.Flush() != nil {
		if time.Now().After(deadline) {
			t.Fatal("ClickHouse 恢复后应能全部写完")
		}
	}
	seen := map[string]int{}
	for _, id := range conn.sent {
		seen[id]++
	}
	if len(seen) != writers*perWriter {
		t.Errorf("应写入 %d 个不同的行，实际 %d", writers*perWriter, len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("行 %s 写入了 %d 次", id, n)
			break
		}
	}
}
