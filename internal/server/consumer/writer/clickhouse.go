// Package writer 实现 ClickHouse 批量写入（Phase 4）
package writer

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
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
	// FIM 上下文:谁改的(username)/谁登录的(login_uid/login_user)/改了什么(content_hash/file_size)
	Username    string
	LoginUID    string
	LoginUser   string
	ContentHash string
	FileSize    string
}

// ClickHouseWriter 将监控指标批量写入 ClickHouse
// conn 为 nil 时所有写入操作为空操作（ClickHouse 未启用）
type ClickHouseWriter struct {
	conn chdriver.Conn
	// authConn 只授了 INSERT 的账号，专写 auth_events（见 WithAuthConn）。
	authConn     chdriver.Conn
	logger       *zap.Logger
	batchSize    int
	flushTimeout time.Duration

	mu         sync.Mutex
	metricRows []hostMetricRow
	fimRows    []fimEventRow
	ebpfRows   []ebpfEventRow
	authRows   []authEventRow

	// retrySince 记录哪些表有写失败、已放回缓冲等待重试的行，以及从何时开始（受 mu 保护）。
	// 有任何一张表时提交屏障不推进 offset。
	//
	// 失败的行必须留在内存里重试，不能指望 offset 不推进来补：同一消费会话内 Kafka
	// 不会重投未提交的消息，而曾经的做法（失败即丢弃批次、只置一个全局标记、下一次任意
	// 表写成功就清除）会在 ClickHouse 一次抖动后静默丢掉那段时间的整批数据——ebpf、
	// 认证日志只写 ClickHouse，丢了就没有副本。
	retrySince map[string]time.Time
	// inflight 已从缓冲取出、正在写入或转存的行数，计入背压上限（受 mu 保护）。
	inflight int
	// room 在刷盘腾出缓冲后被关闭并换新，唤醒因缓冲超限而等待的写入方（受 mu 保护）。
	room        chan struct{}
	maxBuffered int
	// maxRetained 单表待重试的行超过这么多就提前转存，不等 spillAfter。
	maxRetained int
	// spiller 转存写不进 ClickHouse 的行（存 spillerBox）。可在运行中补设（启动时 Kafka
	// 不可用、后台重试成功后），所以用原子读写。未设时只能留在内存里重试。
	spiller atomic.Value

	// flushMu 串行化刷盘：周期刷盘与提交屏障会并发调用 flush，失败行的放回顺序与
	// retrySince 的读写都要求同一时刻只有一个刷盘在进行。
	flushMu sync.Mutex

	flushCh     chan struct{}
	done        chan struct{}
	flusherDone chan struct{}

	// fimInfoOK 表里的 severity 枚举是否已含 info（启动时检查/补齐的结果）。
	// 未补齐时 info 行在预检阶段剔除并计拒收，避免它们进批次后逐行断连重建。
	fimInfoOK atomic.Bool

	rejects rejectLog
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
		// P2-2: 预分配 cap 避免 append 多次 realloc + 大块 GC.
		metricRows:  make([]hostMetricRow, 0, batchSize),
		fimRows:     make([]fimEventRow, 0, batchSize),
		ebpfRows:    make([]ebpfEventRow, 0, batchSize),
		authRows:    make([]authEventRow, 0, 256),
		flushCh:     make(chan struct{}, 1),
		done:        make(chan struct{}),
		flusherDone: make(chan struct{}),
		rejects:     rejectLog{last: map[string]time.Time{}, suppressed: map[string]int{}},
		retrySince:  map[string]time.Time{},
		room:        make(chan struct{}),
		maxBuffered: defaultMaxBuffered,
		maxRetained: defaultMaxBuffered / 2,
	}
	if conn != nil {
		// 启动时确保新增 schema 已建（init.sql 只在首次跑，已部署环境的 CH 需 runtime ensure）
		w.ensureSchemas()
		go w.flusher()
	}
	return w
}

// WithAuthConn 让 auth_events 的写入改用另一个连接（只授 INSERT 的账号）。
//
// 设置后不再退回主连接：这个账号连不上、没权限时，auth_events 的写入失败、照常转存待回放，
// 写入失败的指标也会亮——悄悄改用主账号写，配置错了也没人知道，账号隔离就形同虚设。
// 建表与加列仍走主连接，这个账号不需要 DDL 权限。
func (w *ClickHouseWriter) WithAuthConn(conn chdriver.Conn) *ClickHouseWriter {
	w.authConn = conn
	return w
}

// connFor 返回写某张表用的连接。
func (w *ClickHouseWriter) connFor(table string) chdriver.Conn {
	if table == "auth_events" && w.authConn != nil {
		return w.authConn
	}
	return w.conn
}

// fim_events.severity 的旧定义与新定义，新定义须与 deploy/init-clickhouse.sql 一致。
// 类型名按 system.columns 的写法（等号两侧带空格）。
const (
	fimSeverityOldType = "Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4)"
	fimSeverityNewType = "Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4)"
)

// ensureFIMSeverityInfo 给存量表的 fim_events.severity 补上 info。
//
// fim 插件 1.0.2 起把与包数据库一致的变更标成 info，旧表的枚举没有这个值。
// 只在列类型恰好是旧定义时才改：只加枚举值是元数据变更；若类型是别的样子（有人手工改过），
// 照新定义 MODIFY 可能删掉枚举值、触发重写数据的变更，这时只报错交给人处理。
func (w *ClickHouseWriter) ensureFIMSeverityInfo() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var colType string
	err := w.conn.QueryRow(ctx,
		"SELECT type FROM system.columns WHERE database = currentDatabase() AND table = 'fim_events' AND name = 'severity'",
	).Scan(&colType)
	if err != nil {
		w.logger.Error("读取 fim_events.severity 类型失败，info 级别的 FIM 事件可能被拒收", zap.Error(err))
		return
	}
	switch colType {
	case fimSeverityNewType:
		w.fimInfoOK.Store(true)
		return
	case fimSeverityOldType:
		if err := w.conn.Exec(ctx, "ALTER TABLE fim_events MODIFY COLUMN severity "+fimSeverityNewType); err != nil {
			w.logger.Error("fim_events.severity 补 info 失败，info 级别的 FIM 事件会被拒收", zap.Error(err))
			return
		}
		w.fimInfoOK.Store(true)
		w.logger.Info("fim_events.severity 已补上 info")
	default:
		w.logger.Error("fim_events.severity 类型与预期不符，未自动修改", zap.String("type", colType))
	}
}

// ensureSchemas 启动时 CREATE TABLE IF NOT EXISTS 保证新增 CH 表存在。
// 仅添加 init-clickhouse.sql 后新增的表，避免与原 init 重复。
// 失败仅 warn，不阻塞启动（已存在的表 IF NOT EXISTS 是 no-op）。
func (w *ClickHouseWriter) ensureSchemas() {
	ddls := []struct {
		name string
		ddl  string
	}{
		{"auth_events", authEventsDDL},
		// 存量表补服务端接收时间。只加列、带默认值，是元数据变更，不重写数据。
		{"auth_events.received_at", authEventsAddReceivedAt},
		{
			"storyline_events",
			`CREATE TABLE IF NOT EXISTS storyline_events (
				id            UInt64,
				story_id      String,
				host_id       String,
				data_type     Int32,
				event_type    LowCardinality(String),
				pid           String,
				exe           String,
				detail        String,
				rule_name     LowCardinality(String),
				severity      LowCardinality(String),
				timestamp     DateTime64(3),
				created_at    DateTime64(3),
				INDEX idx_detail detail TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 4
			) ENGINE = MergeTree()
			PARTITION BY toYYYYMM(timestamp)
			ORDER BY (story_id, timestamp)
			TTL toDateTime(timestamp) + INTERVAL 90 DAY
			SETTINGS index_granularity = 8192`,
		},
		{
			"alerts",
			`CREATE TABLE IF NOT EXISTS alerts (
				id              UInt64,
				result_id       String,
				host_id         String,
				rule_id         String,
				policy_id       String,
				source          LowCardinality(String),
				severity        LowCardinality(String),
				category        LowCardinality(String),
				title           String,
				description     String,
				actual          String,
				expected        String,
				fix_suggestion  String,
				status          LowCardinality(String),
				first_seen_at   DateTime64(3),
				last_seen_at    DateTime64(3),
				hit_count       UInt32,
				last_notified_at DateTime64(3),
				notify_count    UInt32,
				resolved_at     DateTime64(3),
				resolved_by     String,
				resolve_reason  String,
				created_at      DateTime64(3),
				updated_at      DateTime64(3),
				version         UInt64,
				INDEX idx_host host_id TYPE bloom_filter GRANULARITY 4,
				INDEX idx_title title TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4,
				INDEX idx_result result_id TYPE bloom_filter GRANULARITY 4
			) ENGINE = ReplacingMergeTree(version)
			PARTITION BY toYYYYMM(created_at)
			ORDER BY (result_id)
			TTL toDateTime(created_at) + INTERVAL 365 DAY
			SETTINGS index_granularity = 8192`,
		},
		{
			"vulnerabilities",
			`CREATE TABLE IF NOT EXISTS vulnerabilities (
				id                       UInt64,
				cve_id                   String,
				osv_id                   String,
				purl                     String,
				severity                 LowCardinality(String),
				cvss_score               Float32,
				component                String,
				description              String,
				affected_hosts           UInt32,
				patched_hosts            UInt32,
				status                   LowCardinality(String),
				discovered_at            DateTime64(3),
				patched_at               DateTime64(3),
				current_version          String,
				fixed_version            String,
				reference_url            String,
				cvss_vector              String,
				attack_vector            LowCardinality(String),
				vuln_type                LowCardinality(String),
				affected_versions        String,
				source                   LowCardinality(String),
				patch_available          UInt8,
				epss_score               Float32,
				cwe_id                   String,
				confidence               LowCardinality(String),
				vuln_category            LowCardinality(String),
				restart_action           LowCardinality(String),
				vuln_category_override   String,
				restart_action_override  String,
				cnvd_id                  String,
				cnnvd_id                 String,
				has_exploit              UInt8,
				in_kev                   UInt8,
				created_at               DateTime64(3),
				updated_at               DateTime64(3),
				version                  UInt64,
				INDEX idx_cve cve_id TYPE bloom_filter GRANULARITY 4,
				INDEX idx_purl purl TYPE bloom_filter GRANULARITY 4
			) ENGINE = ReplacingMergeTree(version)
			PARTITION BY toYYYYMM(discovered_at)
			ORDER BY (cve_id)
			TTL toDateTime(discovered_at) + INTERVAL 730 DAY
			SETTINGS index_granularity = 8192`,
		},
		{
			"host_vulnerabilities",
			`CREATE TABLE IF NOT EXISTS host_vulnerabilities (
				id                            UInt64,
				vuln_id                       UInt64,
				host_id                       String,
				hostname                      String,
				ip                            String,
				current_version               String,
				status                        LowCardinality(String),
				patched_at                    DateTime64(3),
				precheck_status               LowCardinality(String),
				precheck_message              String,
				precheck_packages             String,
				precheck_affected_processes   String,
				precheck_checked_at           DateTime64(3),
				created_at                    DateTime64(3),
				updated_at                    DateTime64(3),
				version                       UInt64,
				INDEX idx_host host_id TYPE bloom_filter GRANULARITY 4,
				INDEX idx_vuln vuln_id TYPE bloom_filter GRANULARITY 4
			) ENGINE = ReplacingMergeTree(version)
			PARTITION BY toYYYYMM(created_at)
			ORDER BY (host_id, vuln_id)
			TTL toDateTime(created_at) + INTERVAL 365 DAY
			SETTINGS index_granularity = 8192`,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, t := range ddls {
		if err := w.conn.Exec(ctx, t.ddl); err != nil {
			w.logger.Warn("ClickHouse ensure schema 失败", zap.String("table", t.name), zap.Error(err))
			continue
		}
		w.logger.Info("ClickHouse schema 就绪", zap.String("table", t.name))
	}
	w.ensureFIMSeverityInfo()
}

// Close 触发最终刷新，等它完成后返回。转存器须在此之后关闭：最终刷新可能还要转存。
func (w *ClickHouseWriter) Close() {
	if w.conn != nil {
		close(w.done)
		<-w.flusherDone
	}
}

// Flush 同步刷新当前所有内存批次到 ClickHouse，供提交屏障在推进 offset 前调用。
//
// 返回 nil 表示调用前已缓冲的行全部落盘（或因取值不合表结构被拒收），offset 可以推进；
// 有任何一张表写失败，失败的行已放回缓冲等待重试，返回错误，offset 不得推进。
// 进程在此期间退出也不丢：未提交的 offset 会在重启后被 Kafka 重新投递。
func (w *ClickHouseWriter) Flush() error {
	if w.conn == nil {
		return nil
	}
	w.flush()
	w.mu.Lock()
	defer w.mu.Unlock()
	for table := range w.retrySince {
		return errors.New("ClickHouse 有写失败待重试的数据（" + table + "），offset 不得推进")
	}
	return nil
}

// spillerBox 让 atomic.Value 存放接口值（Value 要求每次存入的具体类型一致）。
type spillerBox struct{ s Spiller }

// SetSpiller 配置转存，可在运行中调用。
func (w *ClickHouseWriter) SetSpiller(s Spiller) {
	w.spiller.Store(spillerBox{s})
}

func (w *ClickHouseWriter) getSpiller() Spiller {
	if b, ok := w.spiller.Load().(spillerBox); ok {
		return b.s
	}
	return nil
}

// WriteHostMetrics 将 DataType 1000/1001 消息追加到 host_metrics 批次
func (w *ClickHouseWriter) WriteHostMetrics(msg *kafka.MQMessage) error {
	if w.conn == nil {
		return nil
	}
	row := w.parseHostMetrics(msg)

	w.mu.Lock()
	w.waitRoomLocked()
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
	w.waitRoomLocked()
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
	w.waitRoomLocked()
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
	defer close(w.flusherDone)
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

// takeRows 取走待写的批次，给缓冲换一个新的底层数组。
//
// 不能写成 rows = rows[:0] 来复用数组：取走的批次要在解锁之后才写入 ClickHouse，
// 这期间新到的行会从下标 0 开始覆盖同一个数组——还没写出去的行被后来的行顶掉，
// 表现为一段事件丢失、紧随其后的一段事件入库两次，量越大越明显，且没有任何报错。
//
// 空的不换；新数组的容量按 capHint 给，不沿用上一批的——否则一次突发之后，
// 每次刷盘都要按峰值容量重新分配一遍。
func takeRows[T any](rows *[]T, capHint int) []T {
	if len(*rows) == 0 {
		return nil
	}
	out := *rows
	*rows = make([]T, 0, capHint)
	return out
}

// flush 取出当前批次分块写入 ClickHouse。写失败的行放回缓冲重试；一张表持续写不进去
// 超过 spillAfter、或积压超过 maxRetained，就把它缓冲里的行转存到 Kafka（等确认）后清空，
// 让 offset 恢复推进——一张表的故障不能把整个 consumer 无限期拦住（心跳等只写 MySQL 的
// 数据也走同一个提交屏障），更不能拖到 Kafka 保留期过后从最新位置重新开始。
func (w *ClickHouseWriter) flush() {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()

	w.mu.Lock()
	metrics := takeRows(&w.metricRows, w.batchSize)
	fim := takeRows(&w.fimRows, w.batchSize)
	ebpf := takeRows(&w.ebpfRows, w.batchSize)
	auth := takeRows(&w.authRows, w.batchSize)
	w.inflight = len(metrics) + len(fim) + len(ebpf) + len(auth)
	w.mu.Unlock()

	flushTable(w, "host_metrics", metrics, &w.metricRows, w.flushHostMetrics)
	flushTable(w, "fim_events", fim, &w.fimRows, w.flushFIMEvents)
	flushTable(w, "ebpf_events", ebpf, &w.ebpfRows, w.flushEBPFEvents)
	flushTable(w, "auth_events", auth, &w.authRows, w.flushAuthEvents)

	w.mu.Lock()
	w.inflight = 0
	close(w.room)
	w.room = make(chan struct{})
	w.mu.Unlock()
}

// flushTable 把一张表的行按 batchSize 分块写入。
//
// 分块是为了让重试的批次不随失败次数越滚越大：一次 INSERT 越大越容易超时，超时又整批
// 重试，会自我放大到永远写不进去。第一块失败后其余块不再尝试（ClickHouse 多半整体不可用），
// 一并放回缓冲最前面，保持先后顺序。被拒收的行（取值不合表结构）重试也写不进去，直接转存。
func flushTable[T any](w *ClickHouseWriter, table string, rows []T, buf *[]T, send func([]T) (bool, map[int]bool)) {
	if len(rows) == 0 {
		return
	}
	var keep, rejectedRows []T
	failed := false
	for start := 0; start < len(rows); start += w.batchSize {
		chunk := rows[start:min(start+w.batchSize, len(rows))]
		if failed {
			keep = append(keep, chunk...)
			continue
		}
		ok, rejected := send(chunk)
		for i := range chunk {
			switch {
			case rejected[i]:
				rejectedRows = append(rejectedRows, chunk[i])
			case !ok:
				keep = append(keep, chunk[i])
			}
		}
		failed = !ok
	}
	if len(rejectedRows) > 0 {
		if err := spillRows(w, table, SpillReasonRejected, rejectedRows); err != nil {
			// 转存不了就留着：下次刷盘它们会再被拒收、再尝试转存，期间不放行 offset。
			// 没配转存时（测试、未启用 Kafka）只能计数后丢弃，否则这些行会永远卡住提交。
			if w.getSpiller() != nil {
				keep = append(rejectedRows, keep...)
			}
		}
	}

	w.mu.Lock()
	if len(keep) == 0 {
		// 每次刷盘都把缓冲整个取走，上一轮放回的行就在这批里；一行不剩说明全部落盘或已转存。
		delete(w.retrySince, table)
		consumermetrics.SetCHRetryRows(table, 0)
		w.mu.Unlock()
		return
	}
	*buf = append(keep, *buf...)
	since, pending := w.retrySince[table]
	if !pending {
		since = time.Now()
		w.retrySince[table] = since
	}
	consumermetrics.SetCHRetryRows(table, len(keep))
	var spill []T
	if w.getSpiller() != nil && (time.Since(since) >= spillAfter || len(*buf) >= w.maxRetained) {
		spill = takeRows(buf, w.batchSize)
		w.inflight += len(spill)
	}
	w.mu.Unlock()
	if spill == nil {
		return
	}

	err := spillRows(w, table, SpillReasonUnavailable, spill)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inflight -= len(spill)
	if err != nil {
		*buf = append(spill, *buf...)
		return
	}
	delete(w.retrySince, table)
	consumermetrics.SetCHRetryRows(table, 0)
}

// spillAfter 一张表连续写不进去这么久，就把它的积压转存到 Kafka、恢复推进 offset。
// 期间整个 consumer 的 offset 都停着（含心跳），不能太长；也不能太短，免得一次重启或
// 短暂抖动就把数据转存出去、要人工回放。
var spillAfter = 2 * time.Minute

// defaultMaxBuffered 内存里最多缓冲这么多行（四张表合计，含正在写的）。超过后写入方开始
// 等待，消费随之放慢。正常情况下转存会在远未到这个量之前把积压清掉。
const defaultMaxBuffered = 200000

// backpressureWait 写入方一次最多等这么久。不能无限等：停机与重平衡要等消息处理返回，
// 消费组关闭只给 15 秒。超时后照常追加（offset 未提交，不丢），并计数。
var backpressureWait = 5 * time.Second

// bufferedLocked 当前缓冲的总行数，含正在写的。调用时持有 mu。
func (w *ClickHouseWriter) bufferedLocked() int {
	return len(w.metricRows) + len(w.fimRows) + len(w.ebpfRows) + len(w.authRows) + w.inflight
}

// waitRoomLocked 缓冲超过上限时等刷盘腾出空间，最多等 backpressureWait。调用时持有 mu。
func (w *ClickHouseWriter) waitRoomLocked() {
	if w.bufferedLocked() < w.maxBuffered {
		return
	}
	select {
	case w.flushCh <- struct{}{}:
	default:
	}
	timer := time.NewTimer(backpressureWait)
	defer timer.Stop()
	for w.bufferedLocked() >= w.maxBuffered {
		room := w.room
		w.mu.Unlock()
		select {
		case <-room:
			w.mu.Lock()
		case <-timer.C:
			w.mu.Lock()
			consumermetrics.RecordCHBackpressureTimeout()
			return
		case <-w.done:
			w.mu.Lock()
			return
		}
	}
}

// flushHostMetrics 批量写入 host_metrics 表
// 返回是否全部落盘成功。失败置黏性标记，阻止提交屏障推进 offset。
func (w *ClickHouseWriter) flushHostMetrics(rows []hostMetricRow) (bool, map[int]bool) {
	return w.sendRows("host_metrics",
		"INSERT INTO host_metrics (timestamp, host_id, hostname, cpu_usage, mem_usage, disk_usage, load_1, load_5, load_15, net_in, net_out, disk_read_bytes, disk_write_bytes)",
		len(rows), nil, func(batch chdriver.Batch, i int) error {
			r := rows[i]
			return rowErr(r.HostID, "", batch.Append(
				r.Timestamp, r.HostID, r.Hostname,
				r.CPUUsage, r.MemUsage, r.DiskUsage,
				r.Load1, r.Load5, r.Load15,
				r.NetIn, r.NetOut,
				r.DiskReadBytes, r.DiskWriteBytes,
			))
		})
}

// flushFIMEvents 批量写入 fim_events 表
// 返回是否全部落盘成功。失败置黏性标记，阻止提交屏障推进 offset。
func (w *ClickHouseWriter) flushFIMEvents(rows []fimEventRow) (bool, map[int]bool) {
	return w.sendRows("fim_events",
		"INSERT INTO fim_events (timestamp, host_id, hostname, file_path, change_type, severity, category, detail, trace_id)",
		len(rows), func(i int) error {
			r := rows[i]
			if !fimSeverities[r.Severity] || (r.Severity == "info" && !w.fimInfoOK.Load()) {
				return fmt.Errorf("severity %.32q 不在表的枚举里 (host_id=%s trace_id=%s file_path=%q)", r.Severity, r.HostID, r.TraceID, r.FilePath)
			}
			if !fimChangeTypes[r.ChangeType] {
				return fmt.Errorf("change_type %.32q 不在表的枚举里 (host_id=%s trace_id=%s file_path=%q)", r.ChangeType, r.HostID, r.TraceID, r.FilePath)
			}
			return nil
		}, func(batch chdriver.Batch, i int) error {
			r := rows[i]
			return rowErr(r.HostID, r.TraceID, batch.Append(
				r.Timestamp, r.HostID, r.Hostname,
				r.FilePath, r.ChangeType, r.Severity,
				r.Category, r.Detail, r.TraceID,
			))
		})
}

// flushEBPFEvents 批量写入 ebpf_events 表
// 返回是否全部落盘成功。失败置黏性标记，阻止提交屏障推进 offset。
func (w *ClickHouseWriter) flushEBPFEvents(rows []ebpfEventRow) (bool, map[int]bool) {
	return w.sendRows("ebpf_events",
		"INSERT INTO ebpf_events (timestamp, host_id, hostname, event_type, data_type, pid, ppid, exe, cmdline, parent_exe, file_path, remote_addr, remote_port, local_addr, local_port, protocol, uid, gid, return_code, username, login_uid, login_user, content_hash, file_size)",
		len(rows), nil, func(batch chdriver.Batch, i int) error {
			r := rows[i]
			return rowErr(r.HostID, "", batch.Append(
				r.Timestamp, r.HostID, r.Hostname,
				r.EventType, r.DataType,
				r.PID, r.PPID, r.Exe, r.Cmdline, r.ParentExe,
				r.FilePath, r.RemoteAddr, r.RemotePort, r.LocalAddr, r.LocalPort, r.Protocol,
				r.UID, r.GID, r.ReturnCode,
				r.Username, r.LoginUID, r.LoginUser, r.ContentHash, r.FileSize,
			))
		})
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
			row.Cmdline = sanitize.Cmdline(fields["cmdline"])
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
			row.Username = fields["username"]
			row.LoginUID = fields["login_uid"]
			row.LoginUser = fields["login_user"]
			row.ContentHash = fields["content_hash"]
			row.FileSize = fields["file_size"]
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
			// fim 插件上报的字段叫 change_detail（plugins/fim/main.go），MySQL 写入也读它。
			// 这里曾读 detail，于是 ClickHouse 里的明细恒为空，控制台的事件列表又优先读
			// ClickHouse——前后哈希、大小、权限全部看不到。detail 只作为旧格式的兼容回落。
			row.Detail = fields["change_detail"]
			if row.Detail == "" {
				row.Detail = fields["detail"]
			}
		}
	}
	return row
}

func parseFloat32(s string) float32 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 32)
	// NaN/Inf 来自主机上报，ClickHouse 收得下，但转存时 JSON 序列化不了，会让这张表
	// 在 ClickHouse 宕机时永远转存不出去。指标里它们没有意义，归 0。
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
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

// recordWriteError 记录一次写失败。失败的行由 flushTable 放回缓冲重试，提交屏障在它们
// 落盘前不推进 offset。结果不明的失败（如超时）重试可能产生重复行——归档里多几行
// 远好过证据凭空消失。
func (w *ClickHouseWriter) recordWriteError(table string, rows int) {
	consumermetrics.RecordCHWriteError(table)
	w.logger.Error("ClickHouse 写入失败，这批行留在内存里重试，期间 offset 不推进",
		zap.String("table", table),
		zap.Int("rows", rows))
}
