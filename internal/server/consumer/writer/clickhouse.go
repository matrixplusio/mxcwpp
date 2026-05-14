// Package writer 实现 ClickHouse 批量写入（Phase 4）
package writer

import (
	"context"
	"strconv"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
)

// hostMetricRow 是 host_metrics 表的一行数据
type hostMetricRow struct {
	Timestamp      time.Time
	HostID         string
	Hostname       string
	CPUUsage       float32
	MemUsage       float32
	DiskUsage      float32
	Load1          float32
	Load5          float32
	Load15         float32
	NetIn          uint64
	NetOut         uint64
	DiskReadBytes  uint64
	DiskWriteBytes uint64
}

// fimEventRow 是 fim_events 表的一行数据（ClickHouse 归档）
type fimEventRow struct {
	Timestamp  time.Time
	HostID     string
	Hostname   string
	FilePath   string
	ChangeType string
	Severity   string
	Category   string
	Detail     string
	TraceID    string
}

// ebpfEventRow 是 ebpf_events 表的一行数据
type ebpfEventRow struct {
	Timestamp  time.Time
	HostID     string
	Hostname   string
	EventType  string // process_exec, file_open, tcp_connect
	DataType   int32
	PID        string
	PPID       string
	Exe        string
	Cmdline    string
	ParentExe  string
	FilePath   string
	RemoteAddr string
	RemotePort string
	LocalAddr  string
	LocalPort  string
	Protocol   string
	UID        string
	GID        string
	ReturnCode string
}

// ClickHouseWriter 将监控指标批量写入 ClickHouse
// conn 为 nil 时所有写入操作为空操作（ClickHouse 未启用）
type ClickHouseWriter struct {
	conn         chdriver.Conn
	logger       *zap.Logger
	batchSize    int
	flushTimeout time.Duration

	mu         sync.Mutex
	metricRows []hostMetricRow
	fimRows    []fimEventRow
	ebpfRows   []ebpfEventRow

	flushCh chan struct{}
	done    chan struct{}
}

// NewClickHouseWriter 创建 ClickHouseWriter
// conn 可为 nil（ClickHouse 未启用时跳过写入）
func NewClickHouseWriter(conn chdriver.Conn, batchSize int, flushTimeout time.Duration, logger *zap.Logger) *ClickHouseWriter {
	if batchSize <= 0 {
		batchSize = 5000
	}
	if flushTimeout <= 0 {
		flushTimeout = 10 * time.Second
	}
	w := &ClickHouseWriter{
		conn:         conn,
		logger:       logger,
		batchSize:    batchSize,
		flushTimeout: flushTimeout,
		flushCh:      make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	if conn != nil {
		go w.flusher()
	}
	return w
}

// Close 触发最终刷新并关闭后台 goroutine
func (w *ClickHouseWriter) Close() {
	if w.conn != nil {
		close(w.done)
	}
}

// WriteHostMetrics 将 DataType 1000/1001 消息追加到 host_metrics 批次
func (w *ClickHouseWriter) WriteHostMetrics(msg *kafka.MQMessage) error {
	if w.conn == nil {
		return nil
	}
	row := w.parseHostMetrics(msg)

	w.mu.Lock()
	w.metricRows = append(w.metricRows, row)
	shouldFlush := len(w.metricRows) >= w.batchSize
	w.mu.Unlock()

	if shouldFlush {
		select {
		case w.flushCh <- struct{}{}:
		default:
		}
	}
	return nil
}

// WriteFIMEvent 将 DataType 6001 消息追加到 fim_events 批次（ClickHouse 归档）
func (w *ClickHouseWriter) WriteFIMEvent(msg *kafka.MQMessage) error {
	if w.conn == nil {
		return nil
	}
	row := w.parseFIMEvent(msg)

	w.mu.Lock()
	w.fimRows = append(w.fimRows, row)
	shouldFlush := len(w.fimRows) >= w.batchSize
	w.mu.Unlock()

	if shouldFlush {
		select {
		case w.flushCh <- struct{}{}:
		default:
		}
	}
	return nil
}

// WriteEBPFEvent 将 DataType 3000-3002 消息追加到 ebpf_events 批次
func (w *ClickHouseWriter) WriteEBPFEvent(msg *kafka.MQMessage) error {
	if w.conn == nil {
		return nil
	}
	row := w.parseEBPFEvent(msg)

	w.mu.Lock()
	w.ebpfRows = append(w.ebpfRows, row)
	shouldFlush := len(w.ebpfRows) >= w.batchSize
	w.mu.Unlock()

	if shouldFlush {
		select {
		case w.flushCh <- struct{}{}:
		default:
		}
	}
	return nil
}

// flusher 后台定时/按量刷新批次到 ClickHouse
func (w *ClickHouseWriter) flusher() {
	ticker := time.NewTicker(w.flushTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.flush()
		case <-w.flushCh:
			w.flush()
		case <-w.done:
			w.flush() // 退出前最终刷新
			return
		}
	}
}

// flush 取出当前批次并写入 ClickHouse
func (w *ClickHouseWriter) flush() {
	w.mu.Lock()
	metrics := w.metricRows
	fim := w.fimRows
	ebpf := w.ebpfRows
	w.metricRows = nil
	w.fimRows = nil
	w.ebpfRows = nil
	w.mu.Unlock()

	if len(metrics) > 0 {
		w.flushHostMetrics(metrics)
	}
	if len(fim) > 0 {
		w.flushFIMEvents(fim)
	}
	if len(ebpf) > 0 {
		w.flushEBPFEvents(ebpf)
	}
}

// flushHostMetrics 批量写入 host_metrics 表
func (w *ClickHouseWriter) flushHostMetrics(rows []hostMetricRow) {
	ctx := context.Background()
	batch, err := w.conn.PrepareBatch(ctx,
		"INSERT INTO host_metrics (timestamp, host_id, hostname, cpu_usage, mem_usage, disk_usage, load_1, load_5, load_15, net_in, net_out, disk_read_bytes, disk_write_bytes)",
	)
	if err != nil {
		w.logger.Error("ClickHouse PrepareBatch host_metrics 失败", zap.Error(err))
		return
	}
	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp, r.HostID, r.Hostname,
			r.CPUUsage, r.MemUsage, r.DiskUsage,
			r.Load1, r.Load5, r.Load15,
			r.NetIn, r.NetOut,
			r.DiskReadBytes, r.DiskWriteBytes,
		); err != nil {
			w.logger.Warn("ClickHouse Append host_metrics 失败", zap.Error(err))
		}
	}
	if err := batch.Send(); err != nil {
		w.logger.Error("ClickHouse Send host_metrics 失败",
			zap.Int("rows", len(rows)),
			zap.Error(err),
		)
	} else {
		w.logger.Debug("ClickHouse host_metrics 写入成功", zap.Int("rows", len(rows)))
	}
}

// flushFIMEvents 批量写入 fim_events 表
func (w *ClickHouseWriter) flushFIMEvents(rows []fimEventRow) {
	ctx := context.Background()
	batch, err := w.conn.PrepareBatch(ctx,
		"INSERT INTO fim_events (timestamp, host_id, hostname, file_path, change_type, severity, category, detail, trace_id)",
	)
	if err != nil {
		w.logger.Error("ClickHouse PrepareBatch fim_events 失败", zap.Error(err))
		return
	}
	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp, r.HostID, r.Hostname,
			r.FilePath, r.ChangeType, r.Severity,
			r.Category, r.Detail, r.TraceID,
		); err != nil {
			w.logger.Warn("ClickHouse Append fim_events 失败", zap.Error(err))
		}
	}
	if err := batch.Send(); err != nil {
		w.logger.Error("ClickHouse Send fim_events 失败",
			zap.Int("rows", len(rows)),
			zap.Error(err),
		)
	} else {
		w.logger.Debug("ClickHouse fim_events 写入成功", zap.Int("rows", len(rows)))
	}
}

// flushEBPFEvents 批量写入 ebpf_events 表
func (w *ClickHouseWriter) flushEBPFEvents(rows []ebpfEventRow) {
	ctx := context.Background()
	batch, err := w.conn.PrepareBatch(ctx,
		"INSERT INTO ebpf_events (timestamp, host_id, hostname, event_type, data_type, pid, ppid, exe, cmdline, parent_exe, file_path, remote_addr, remote_port, local_addr, local_port, protocol, uid, gid, return_code)",
	)
	if err != nil {
		w.logger.Error("ClickHouse PrepareBatch ebpf_events 失败", zap.Error(err))
		return
	}
	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp, r.HostID, r.Hostname,
			r.EventType, r.DataType,
			r.PID, r.PPID, r.Exe, r.Cmdline, r.ParentExe,
			r.FilePath, r.RemoteAddr, r.RemotePort, r.LocalAddr, r.LocalPort, r.Protocol,
			r.UID, r.GID, r.ReturnCode,
		); err != nil {
			w.logger.Warn("ClickHouse Append ebpf_events 失败", zap.Error(err))
		}
	}
	if err := batch.Send(); err != nil {
		w.logger.Error("ClickHouse Send ebpf_events 失败",
			zap.Int("rows", len(rows)),
			zap.Error(err),
		)
	} else {
		w.logger.Debug("ClickHouse ebpf_events 写入成功", zap.Int("rows", len(rows)))
	}
}

// parseEBPFEvent 从 MQMessage 解析出 ebpfEventRow
func (w *ClickHouseWriter) parseEBPFEvent(msg *kafka.MQMessage) ebpfEventRow {
	row := ebpfEventRow{
		HostID:    msg.AgentID,
		Hostname:  msg.Hostname,
		DataType:  msg.DataType,
		Timestamp: time.Now(),
	}
	if msg.AgentTime > 0 {
		row.Timestamp = time.Unix(msg.AgentTime, 0)
	}

	if len(msg.Body) > 0 {
		if fields, err := ParseRecordFields(msg.Body); err == nil {
			row.EventType = fields["event_type"]
			row.PID = fields["pid"]
			row.PPID = fields["ppid"]
			row.Exe = fields["exe"]
			row.Cmdline = fields["cmdline"]
			row.ParentExe = fields["parent_exe"]
			row.FilePath = fields["file_path"]
			row.RemoteAddr = fields["remote_addr"]
			row.RemotePort = fields["remote_port"]
			row.LocalAddr = fields["local_addr"]
			row.LocalPort = fields["local_port"]
			row.Protocol = fields["protocol"]
			row.UID = fields["uid"]
			row.GID = fields["gid"]
			row.ReturnCode = fields["return_code"]
		}
	}
	return row
}

// parseHostMetrics 从 MQMessage 解析出 hostMetricRow
// Body 是 protobuf 编码的 bridge.Payload（map<string,string> fields）
func (w *ClickHouseWriter) parseHostMetrics(msg *kafka.MQMessage) hostMetricRow {
	row := hostMetricRow{
		HostID:    msg.AgentID,
		Hostname:  msg.Hostname,
		Timestamp: time.Now(),
	}
	if msg.AgentTime > 0 {
		row.Timestamp = time.Unix(msg.AgentTime, 0)
	}

	if len(msg.Body) > 0 {
		if fields, err := ParseRecordFields(msg.Body); err == nil {
			row.CPUUsage = parseFloat32(fields["cpu_usage"])
			row.MemUsage = parseFloat32(fields["mem_usage"])
			row.DiskUsage = parseFloat32(fields["disk_usage"])
			row.Load1 = parseFloat32(fields["load_1"])
			row.Load5 = parseFloat32(fields["load_5"])
			row.Load15 = parseFloat32(fields["load_15"])
			row.NetIn = parseUint64(fields["net_in"])
			row.NetOut = parseUint64(fields["net_out"])
			row.DiskReadBytes = parseUint64(fields["disk_read_bytes"])
			row.DiskWriteBytes = parseUint64(fields["disk_write_bytes"])
		}
	}
	return row
}

// parseFIMEvent 从 MQMessage 解析出 fimEventRow
func (w *ClickHouseWriter) parseFIMEvent(msg *kafka.MQMessage) fimEventRow {
	row := fimEventRow{
		HostID:    msg.AgentID,
		Hostname:  msg.Hostname,
		TraceID:   msg.TraceID,
		Timestamp: time.Now(),
	}
	if msg.AgentTime > 0 {
		row.Timestamp = time.Unix(msg.AgentTime, 0)
	}

	if len(msg.Body) > 0 {
		if fields, err := ParseRecordFields(msg.Body); err == nil {
			row.FilePath = fields["file_path"]
			row.ChangeType = fields["change_type"]
			row.Severity = fields["severity"]
			row.Category = fields["category"]
			row.Detail = fields["detail"]
		}
	}
	return row
}

func parseFloat32(s string) float32 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 32)
	if err != nil {
		return 0
	}
	return float32(v)
}

func parseUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
