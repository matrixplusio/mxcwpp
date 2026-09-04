package model

import (
	"sync"
	"testing"
)

func resetCHBatchForTest() {
	chBatchMu.Lock()
	defer chBatchMu.Unlock()
	chBatchBuf = map[string]*chPending{}
}

// TestEnqueueIsNoOpWhenClickHouseAbsent 未注入 CH 连接时不得囤积内存。
//
// 没有连接就没有冲刷器；此时还往缓冲里堆，等于把内存漏在一个永远不会被读走的
// map 里。单机部署与测试环境都跑在这条路径上。
func TestEnqueueIsNoOpWhenClickHouseAbsent(t *testing.T) {
	resetCHBatchForTest()
	open := chSyncOpen
	chSyncOpen = false
	t.Cleanup(func() { chSyncOpen = open; resetCHBatchForTest() })

	for i := 0; i < 100; i++ {
		chEnqueue("alerts", "INSERT INTO alerts (id)", uint64(i))
	}

	chBatchMu.Lock()
	defer chBatchMu.Unlock()
	if len(chBatchBuf) != 0 {
		t.Fatalf("CH 未接入时仍缓存了 %d 条语句的数据", len(chBatchBuf))
	}
}

// TestEnqueueGroupsByStatement 同一条 INSERT 的多行攒在一起。
//
// 攒批的全部意义在此：ClickHouse 每次 INSERT 产出一个 part，逐行发送会让
// 一张五万行的表一天新建几百万个 part，合并压力压垮存储节点。
func TestEnqueueGroupsByStatement(t *testing.T) {
	resetCHBatchForTest()
	open := chSyncOpen
	chSyncOpen = true
	t.Cleanup(func() { chSyncOpen = open; resetCHBatchForTest() })

	const stmtA = "INSERT INTO alerts (id)"
	const stmtB = "INSERT INTO vulnerabilities (id)"
	for i := 0; i < 10; i++ {
		chEnqueue("alerts", stmtA, uint64(i))
	}
	chEnqueue("vulnerabilities", stmtB, uint64(1))

	chBatchMu.Lock()
	defer chBatchMu.Unlock()
	if got := len(chBatchBuf[stmtA].rows); got != 10 {
		t.Errorf("alerts 攒了 %d 行，应为 10", got)
	}
	if got := len(chBatchBuf[stmtB].rows); got != 1 {
		t.Errorf("vulnerabilities 攒了 %d 行，应为 1", got)
	}
	if chBatchBuf[stmtA].table != "alerts" {
		t.Errorf("表名记错了: %q", chBatchBuf[stmtA].table)
	}
}

// TestEnqueueIsConcurrencySafe 钩子从多个 goroutine 触发，缓冲必须扛得住。
func TestEnqueueIsConcurrencySafe(t *testing.T) {
	resetCHBatchForTest()
	open := chSyncOpen
	chSyncOpen = true
	t.Cleanup(func() { chSyncOpen = open; resetCHBatchForTest() })

	const stmt = "INSERT INTO alerts (id)"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			// 每个 goroutine 少于单批上限，避免触发冲刷（冲刷会去连 CH）。
			for j := 0; j < 20; j++ {
				chEnqueue("alerts", stmt, uint64(base*100+j))
			}
		}(i)
	}
	wg.Wait()

	chBatchMu.Lock()
	defer chBatchMu.Unlock()
	if got := len(chBatchBuf[stmt].rows); got != 160 {
		t.Fatalf("并发入队后有 %d 行，应为 160——有行丢了", got)
	}
}

// TestFlushClearsBuffer 冲刷后缓冲必须清空。
//
// 不清空就会重复发送同一批，ReplacingMergeTree 虽能去重，
// part 数却照样翻倍——正是攒批要解决的问题本身。
func TestFlushClearsBuffer(t *testing.T) {
	resetCHBatchForTest()
	open := chSyncOpen
	chSyncOpen = true
	t.Cleanup(func() { chSyncOpen = open; resetCHBatchForTest() })

	chEnqueue("alerts", "INSERT INTO alerts (id)", uint64(1))
	// chConn 为 nil，发送必然失败；这里验的是缓冲的交接，不是发送本身。
	func() {
		defer func() { _ = recover() }()
		chFlush()
	}()

	chBatchMu.Lock()
	defer chBatchMu.Unlock()
	if len(chBatchBuf) != 0 {
		t.Fatal("冲刷后缓冲未清空，同一批会被重复发送")
	}
}
