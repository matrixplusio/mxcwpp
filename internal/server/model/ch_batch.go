package model

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ClickHouse 写入缓冲。
//
// 为什么需要：同步逻辑挂在 GORM 的 AfterCreate / AfterUpdate 上，一行一次
// chConn.Exec，而 ClickHouse 每次 INSERT 都产出一个 part。高频更新的表会因此
// 一天新建的 part 数比逻辑行数还多两个数量级、每个仅一行——存储节点的合并
// 压力几乎全部来自这里。
//
// 缓冲把同一条 INSERT 语句的多行攒起来，用 PrepareBatch 一次发出，一批一个 part。
//
// 代价是异步：进程被杀时缓冲里的行会丢。可以接受——MySQL 才是事实来源，
// CH 侧是 ReplacingMergeTree 的镜像，缺行由 cmd/tools/etl-alerts-vulns-ch 回补。
// 不可接受的是让业务写入路径等待 CH。
const (
	chBatchMaxRows  = 500              // 单批上限，到了立即冲刷
	chBatchInterval = 2 * time.Second  // 冲刷周期，保证低峰期也能及时落库
	chBatchTimeout  = 15 * time.Second // 单批发送超时，比单行的 3s 宽，一批更大
)

type chPending struct {
	table string
	rows  [][]any
}

var (
	chBatchMu      sync.Mutex
	chBatchBuf     = map[string]*chPending{} // INSERT 语句 → 待发送行
	chBatchStarted bool
)

// chEnqueue 把一行排入缓冲。stmt 是不带 VALUES 的 INSERT 语句。
func chEnqueue(table, stmt string, args ...any) {
	if !chSyncOpen {
		return
	}

	chBatchMu.Lock()
	p := chBatchBuf[stmt]
	if p == nil {
		p = &chPending{table: table}
		chBatchBuf[stmt] = p
	}
	p.rows = append(p.rows, args)
	full := len(p.rows) >= chBatchMaxRows
	chBatchMu.Unlock()

	if full {
		chFlush()
	}
}

// startCHFlusher 启动周期冲刷。由 SetClickHouse 调用，不对外暴露——
// 让它「忘了启动」在结构上不可能发生：能入队就一定已经启动过。
func startCHFlusher() {
	chBatchMu.Lock()
	if chBatchStarted {
		chBatchMu.Unlock()
		return
	}
	chBatchStarted = true
	chBatchMu.Unlock()

	go func() {
		t := time.NewTicker(chBatchInterval)
		defer t.Stop()
		for range t.C {
			chFlush()
		}
	}()
}

// chFlush 把缓冲里的所有语句各发一批。
func chFlush() {
	chBatchMu.Lock()
	pending := chBatchBuf
	if len(pending) == 0 {
		chBatchMu.Unlock()
		return
	}
	chBatchBuf = map[string]*chPending{}
	chBatchMu.Unlock()

	for stmt, p := range pending {
		if len(p.rows) == 0 {
			continue
		}
		if err := chSendBatch(stmt, p); err != nil {
			chLogError(p.table, err)
		}
	}
}

func chSendBatch(stmt string, p *chPending) error {
	ctx, cancel := context.WithTimeout(context.Background(), chBatchTimeout)
	defer cancel()

	batch, err := chConn.PrepareBatch(ctx, stmt)
	if err != nil {
		return err
	}
	for _, row := range p.rows {
		if err := batch.Append(row...); err != nil {
			// 单行不合法不该拖垮整批：记下来，继续发其余的。
			if chSyncLog != nil {
				chSyncLog.Warn("ClickHouse 批次内单行追加失败",
					zap.String("table", p.table), zap.Error(err))
			}
			continue
		}
	}
	return batch.Send()
}
