package writer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

// 转存原因。
const (
	// SpillReasonUnavailable ClickHouse 持续写不进去，积压超时或超量。
	SpillReasonUnavailable = "clickhouse_unavailable"
	// SpillReasonRejected 取值与表结构不符被拒收；补好表结构后可回放。
	SpillReasonRejected = "rejected"
)

// spillRecordBytes 每条转存记录的行数据最多这么多字节，远小于 Kafka 的 4MB 消息上限
// （上限按未压缩大小在客户端检查）。按字节而不是按行数切：单行大小由主机决定。
const spillRecordBytes = 1 << 20

// spillMaxRowBytes 单行序列化后超过这个大小就不转存，隔离丢弃：它放不进任何一条消息，
// 留着只会让这张表永远转存不出去、整个 consumer 永远停止提交 offset。
const spillMaxRowBytes = spillRecordBytes

// SpillRecord 是一条转存记录：同一张表的若干行，按该表的行结构序列化成 JSON 数组。
type SpillRecord struct {
	Table    string          `json:"table"`
	Reason   string          `json:"reason"`
	FailedAt time.Time       `json:"failed_at"`
	Rows     json.RawMessage `json:"rows"`
}

// Spiller 持久转存写不进 ClickHouse 的行。Spill 必须在数据被确认落盘（Kafka 已确认）后
// 才返回 nil：返回 nil 后这些行会从内存删除、对应 offset 随之提交。
type Spiller interface {
	Spill(records []SpillRecord) error
}

var errNoSpiller = errors.New("未配置转存")

// spillRows 把一张表的行逐行序列化、按字节装块后转存。序列化不了或过大的行隔离丢弃并
// 计数告警，不让它拦住其余的行。部分块已确认、后续块失败时返回错误，调用方整批重试，
// 已确认的块会在转存主题里重复一份——回放时多写几行好过少写。
func spillRows[T any](w *ClickHouseWriter, table, reason string, rows []T) error {
	sp := w.getSpiller()
	if sp == nil {
		consumermetrics.RecordCHSpillFailure(table)
		return errNoSpiller
	}
	now := time.Now()
	var records []SpillRecord
	var cur []byte
	flushRec := func() {
		if len(cur) == 0 {
			return
		}
		records = append(records, SpillRecord{Table: table, Reason: reason, FailedAt: now, Rows: append(append([]byte{'['}, cur...), ']')})
		cur = nil
	}
	dropped := 0
	for i := range rows {
		b, err := marshalRow(rows[i])
		if err != nil || len(b) > spillMaxRowBytes {
			dropped++
			consumermetrics.RecordCHRowDropped(table)
			w.logger.Error("这一行无法转存，已隔离丢弃",
				zap.String("table", table), zap.String("host_id", rowHostID(rows[i])),
				zap.Int("bytes", len(b)), zap.Error(err))
			continue
		}
		if len(cur)+len(b)+1 > spillRecordBytes {
			flushRec()
		}
		if len(cur) > 0 {
			cur = append(cur, ',')
		}
		cur = append(cur, b...)
	}
	flushRec()
	if len(records) == 0 {
		return nil
	}
	if err := sp.Spill(records); err != nil {
		consumermetrics.RecordCHSpillFailure(table)
		w.logger.Error("转存失败，这些行留在内存里，offset 不推进",
			zap.String("table", table), zap.String("reason", reason), zap.Int("rows", len(rows)), zap.Error(err))
		return err
	}
	consumermetrics.RecordCHSpilled(table, reason, len(rows)-dropped)
	w.logger.Warn("已把写不进 ClickHouse 的行转存到 Kafka，待回放",
		zap.String("table", table), zap.String("reason", reason), zap.Int("rows", len(rows)-dropped))
	return nil
}

// marshalRow 序列化一行，不做 HTML 转义：默认的 < > & 转义会把长度放大到 6 倍，
// 主机上报的明细里这些字符可以任意多。
func marshalRow(row any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(row); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// rowHostID 取行的主机标识，供隔离日志定位。
func rowHostID(row any) string {
	switch r := row.(type) {
	case hostMetricRow:
		return r.HostID
	case fimEventRow:
		return r.HostID
	case ebpfEventRow:
		return r.HostID
	case authEventRow:
		return r.HostID
	}
	return ""
}

// ReplaySpill 把一条转存记录写回 ClickHouse，供回放工具调用。返回写入的行数与被拒收的行数；
// 返回错误时一行都不算写入（调用方不要提交这条记录的 offset）。
func (w *ClickHouseWriter) ReplaySpill(rec SpillRecord) (written, rejected int, err error) {
	switch rec.Table {
	case "host_metrics":
		return replayRows(rec, w.flushHostMetrics)
	case "fim_events":
		return replayRows(rec, w.flushFIMEvents)
	case "ebpf_events":
		return replayRows(rec, w.flushEBPFEvents)
	case "auth_events":
		// 转存主题没有鉴权，能连 Kafka 的人就能写进去：回放时重新做解析时的截断与脱敏，
		// 不把转存内容当成已经处理过的可信数据。
		return replayRows(rec, func(rows []authEventRow) (bool, map[int]bool) {
			for i := range rows {
				rows[i].normalize()
			}
			return w.flushAuthEvents(rows)
		})
	}
	return 0, 0, fmt.Errorf("未知的表 %q", rec.Table)
}

func replayRows[T any](rec SpillRecord, send func([]T) (bool, map[int]bool)) (int, int, error) {
	var rows []T
	if err := json.Unmarshal(rec.Rows, &rows); err != nil {
		return 0, 0, fmt.Errorf("解析 %s 的转存行失败: %w", rec.Table, err)
	}
	if len(rows) == 0 {
		return 0, 0, nil
	}
	ok, bad := send(rows)
	if !ok {
		return 0, 0, fmt.Errorf("写入 %s 失败", rec.Table)
	}
	return len(rows) - len(bad), len(bad), nil
}
