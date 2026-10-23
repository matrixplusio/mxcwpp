package writer

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

// maxRejectsPerBatch 一批内最多为 Append 失败重建这么多次批次。已知会失败的取值
// （枚举列）由 rowValidator 在进批次前剔除，不走重建；走到这里的是没预料到的失败，
// 每次重建都要断开并重连 ClickHouse，超过上限按整批失败处理，交给失败标记与告警。
const maxRejectsPerBatch = 32

// sendTimeout 一块数据从建批次到发送完成的时限。
var sendTimeout = 60 * time.Second

// rejectLogInterval 同一张表的拒收日志最多每隔这么久打一条，计数照记。
const rejectLogInterval = time.Minute

// rowAppender 把第 i 行追加进批次。
type rowAppender func(batch chdriver.Batch, i int) error

// rowValidator 在第 i 行进批次前检查取值是否合表结构，不合则返回原因、该行被剔除。
// 可为 nil。
type rowValidator func(i int) error

// rejectLog 按表限频记录拒收日志。
type rejectLog struct {
	mu         sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int
}

// sendRows 把 n 行写进新批次并发送。返回是否全部处理完（落盘或被拒收），以及被拒收
// 的行下标；失败时调用方把未被拒收的行留下重试。
//
// clickhouse-go 在任意一行 Append 失败后会把整个批次标成无效并释放连接，之后 Send
// 必然失败——一行取值不合表结构（如枚举里没有的级别）就会拖垮同批其余所有行。
// 这里把出错的那行剔除、计一次拒收，再用剩下的行重建批次。被拒的行无论重试多少次
// 都写不进去，所以不重试；它们靠拒收指标与告警被看见。
func (w *ClickHouseWriter) sendRows(table, query string, n int, validate rowValidator, appendRow rowAppender) (bool, map[int]bool) {
	// 写入必须有截止时间：驱动只有读超时，网络黑洞时写会一直挂着，期间持有刷盘锁，
	// 提交屏障、重平衡与停机全被卡住。
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	rejected := make(map[int]bool)
	if validate != nil {
		for i := 0; i < n; i++ {
			if err := validate(i); err != nil {
				rejected[i] = true
				w.rejectRow(table, err)
			}
		}
	}
	rebuilds := 0
	for {
		if len(rejected) == n {
			return true, rejected
		}
		batch, err := w.connFor(table).PrepareBatch(ctx, query)
		if err != nil {
			w.logger.Error("ClickHouse PrepareBatch 失败", zap.String("table", table), zap.Error(err))
			w.recordWriteError(table, n-len(rejected))
			return false, rejected
		}

		bad := -1
		for i := 0; i < n; i++ {
			if rejected[i] {
				continue
			}
			if err := appendRow(batch, i); err != nil {
				bad = i
				w.rejectRow(table, err)
				break
			}
		}
		if bad >= 0 {
			_ = batch.Abort()
			rejected[bad] = true
			rebuilds++
			if rebuilds > maxRejectsPerBatch {
				w.logger.Error("ClickHouse 批次内 Append 失败过多，按整批失败处理",
					zap.String("table", table), zap.Int("rows", n), zap.Int("rejected", len(rejected)))
				w.recordWriteError(table, n-len(rejected))
				return false, rejected
			}
			continue
		}

		if err := batch.Send(); err != nil {
			w.logger.Error("ClickHouse Send 失败",
				zap.String("table", table), zap.Int("rows", n-len(rejected)), zap.Error(err))
			w.recordWriteError(table, n-len(rejected))
			return false, rejected
		}
		w.logger.Debug("ClickHouse 写入成功",
			zap.String("table", table), zap.Int("rows", n-len(rejected)), zap.Int("rejected", len(rejected)))
		return true, rejected
	}
}

// rowErr 给 Append 报错带上定位信息，拒收日志里才找得到是哪台主机的哪条上报。
func rowErr(hostID, traceID string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w (host_id=%s trace_id=%s)", err, hostID, traceID)
}

// fim_events 的两个枚举列可取的值，须与 deploy/init-clickhouse.sql 一致。
// 进批次前就剔除不在其中的行：Append 失败要断开连接重建批次，代价高得多。
var (
	fimSeverities  = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	fimChangeTypes = map[string]bool{"added": true, "removed": true, "changed": true}
)

// rejectRow 记一行拒收：指标每次都记，日志按表限频。
func (w *ClickHouseWriter) rejectRow(table string, err error) {
	consumermetrics.RecordCHRowRejected(table)

	w.rejects.mu.Lock()
	now := time.Now()
	if now.Sub(w.rejects.last[table]) < rejectLogInterval {
		w.rejects.suppressed[table]++
		w.rejects.mu.Unlock()
		return
	}
	skipped := w.rejects.suppressed[table]
	w.rejects.last[table] = now
	w.rejects.suppressed[table] = 0
	w.rejects.mu.Unlock()

	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	w.logger.Error("ClickHouse 拒收一行，已跳过（该行取值与表结构不符）",
		zap.String("table", table), zap.String("error", msg), zap.Int("suppressed_since_last_log", skipped))
}
