// Package signals 把 engine 的全部检测命中合并成「信号」写入 ClickHouse。
//
// 单个弱信号（枚举命令、DNS、sudo、端口外连……）不该单独打扰值班，但也不能丢：
// 此前低保真与观察阶段的命中在 engine 里直接 continue，既不告警也不计数，等于这些检测
// 从未存在。engine 把每一次命中（含不告警的）都发到 engine.alert 主题，这里消费它，
// 按「主机 + 阶段 + 规则 + 程序 + 10 分钟」合并后落库，供风险累积、普遍性统计与狩猎使用。
//
// 合并结果只在写进 ClickHouse 之后才提交 offset：写失败时保留在内存里重试，内存满了就
// 暂停消费（背压），不丢、不跳过。信号是从命中派生的数据，主告警链路不经过这里，
// 这里出故障不影响任何告警的产生。
package signals

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
)

// DDL 信号表。建表语句同时在 deploy/init-clickhouse.sql 里（新装），这里的一份给已有的库补建。
//
// 同一个合并键在一个 10 分钟桶里可能写多行（每次刷新写一次增量），查询时按键 sum(hits)。
// 按 (host_id, bucket, rule_id) 排序：最常见的查询是「这台主机这段时间命中了哪些信号」。
const DDL = `CREATE TABLE IF NOT EXISTS signals (
	bucket      DateTime,
	host_id     String,
	stage       LowCardinality(String),
	rule_id     LowCardinality(String),
	rule_name   String,
	severity    LowCardinality(String),
	technique   LowCardinality(String),
	tactic      LowCardinality(String),
	exe         String,
	parent_exe  String,
	cmdline     String,
	hits        UInt32,
	first_seen  DateTime64(3),
	last_seen   DateTime64(3)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (host_id, bucket, rule_id)
TTL bucket + INTERVAL 30 DAY
SETTINGS index_granularity = 8192`

const (
	// bucketSize 合并的时间粒度。
	bucketSize = 10 * time.Minute
	// flushInterval 定期把已合并的增量写入 ClickHouse 并提交 offset。每次刷新会把一个时间桶切成
	// 一段增量行，间隔越短行数越多；2 分钟让一个 10 分钟桶最多写 5 行，提交延迟也可以接受。
	flushInterval = 2 * time.Minute
	// maxKeys 内存里最多积攒的合并键。超过就暂停消费，等写入成功腾出空间。
	maxKeys = 200000
	// perHostMaxKeys 单台主机在一次刷新周期里最多占用的合并键。合并键里的程序路径来自主机上报，
	// 一台主机用随机路径反复执行程序就能造出海量键，把全舰队的信号消费拖停。超出的命中仍然计数，
	// 只是程序路径记为 overflow，不再细分。
	perHostMaxKeys = 2000
	// overflowExe 超出单主机上限后统一使用的程序路径。
	overflowExe = "(overflow)"
	// insertTimeout 单次写入的超时。分区被收回时 Cleanup 要等这次写完，太长会拖住重平衡。
	insertTimeout = 20 * time.Second
	// fieldMaxLen 文本字段入库上限。内容来自主机上报，主机不可信。
	fieldMaxLen = 1024
)

var (
	messagesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_signals_messages_total",
		Help: "Engine hit messages consumed for signals, labeled by result (ok / decode_error / no_host).",
	}, []string{"result"})
	rowsWrittenTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_signals_rows_written_total",
		Help: "Aggregated signal rows written to ClickHouse.",
	})
	writeFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_signals_write_failures_total",
		Help: "Failed attempts to write aggregated signals to ClickHouse; rows are kept and retried.",
	})
	pendingKeys = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_signals_pending_keys",
		Help: "Aggregated signal keys held in memory, not yet written to ClickHouse.",
	})
	overflowTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_signals_host_overflow_total",
		Help: "Hits merged under the overflow key because one host exceeded its per-flush key limit.",
	})
	// lag 信号消费组落后的消息数。主消费组的 lag 指标不覆盖这个组；消费变慢但没停时，
	// 只有它能在积压被主题保留期删掉之前叫醒人。
	prevalenceFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_signals_prevalence_failures_total",
		Help: "Failed hourly prevalence computations; engine keeps the previous table until it goes stale.",
	})
	prevalenceLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_signals_prevalence_last_success_timestamp_seconds",
		Help: "Unix time of the last successful prevalence computation.",
	})
	lag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_signals_lag",
		Help: "Messages the signals consumer group is behind, per partition.",
	}, []string{"partition"})
)

func init() {
	for _, r := range []string{"ok", "decode_error", "no_host"} {
		messagesTotal.WithLabelValues(r).Add(0)
	}
}

// Collectors 返回本包的指标，由 consumer 的独立注册表注册。
//
// consumer 的 /metrics 只暴露它自己的注册表；用 promauto 会落到默认注册表上，指标存在却
// 永远抓不到，依赖它们的告警也就永远不会响。
func Collectors() []prometheus.Collector {
	return []prometheus.Collector{messagesTotal, rowsWrittenTotal, writeFailuresTotal, pendingKeys, overflowTotal, lag,
		prevalenceFailures, prevalenceLastSuccess}
}

// envelope engine.alert 消息里用得到的字段（engine.AlertEnvelope 的子集）。
type envelope struct {
	HostID     string          `json:"host_id"`
	RuleID     string          `json:"rule_id"`
	Stage      string          `json:"stage"`
	Severity   string          `json:"severity"`
	DetectedAt time.Time       `json:"detected_at"`
	Technique  string          `json:"attck_technique"`
	Tactic     string          `json:"attck_tactic"`
	Payload    json.RawMessage `json:"payload"`
}

type key struct {
	bucket int64
	host   string
	stage  string
	rule   string
	exe    string
}

type row struct {
	Bucket    time.Time
	HostID    string
	Stage     string
	RuleID    string
	RuleName  string
	Severity  string
	Technique string
	Tactic    string
	Exe       string
	ParentExe string
	Cmdline   string
	Hits      uint32
	FirstSeen time.Time
	LastSeen  time.Time
}

type topicPartition struct {
	topic     string
	partition int32
}

// Sink 合并命中并写入 ClickHouse。实现 sarama.ConsumerGroupHandler。
type Sink struct {
	conn chdriver.Conn
	log  *zap.Logger

	mu       sync.Mutex
	rows     map[key]*row
	hostKeys map[string]int           // 每台主机在 rows 里占用的键数
	marks    map[topicPartition]int64 // 已并入 rows、尚未写入的最大 offset

	// insert 写入一批行，测试时替换。
	insert func(ctx context.Context, rows []*row) error
	now    func() time.Time
}

// New 构造 Sink。conn 为空时 Run 直接返回。
func New(conn chdriver.Conn, logger *zap.Logger) *Sink {
	s := &Sink{
		conn:     conn,
		log:      logger,
		rows:     make(map[key]*row),
		hostKeys: make(map[string]int),
		marks:    make(map[topicPartition]int64),
		now:      time.Now,
	}
	s.insert = s.insertCH
	return s
}

// EnsureTable 补建信号表。
func (s *Sink) EnsureTable(ctx context.Context) error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Exec(ctx, DDL)
}

// Run 以独立消费组消费 topic，直到 ctx 取消。与主消费组分开：信号链路的快慢、故障
// 不影响事件落库与告警。
func (s *Sink) Run(ctx context.Context, brokers []string, topic, groupID string) error {
	if s.conn == nil {
		return nil
	}
	// 启动那一刻 ClickHouse 可能短暂不可用：一直重试，不能因为一次失败就让信号链路永久退出。
	for wait := time.Second; ; wait = min(wait*2, time.Minute) {
		err := s.EnsureTable(ctx)
		if err == nil {
			break
		}
		writeFailuresTotal.Inc()
		s.log.Warn("补建信号表失败，稍后重试", zap.Duration("wait", wait), zap.Error(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_6_0_0
	cfg.Consumer.Return.Errors = true
	// 从最早位点开始。这个设置还决定「已提交的位点已被主题保留期删掉」时回到哪里：
	// 设成最新的话，ClickHouse 长时间不可写之后恢复，会连同仍在保留期内的积压一起跳过，
	// 而且没有任何迹象。新消费组首次启动会补一遍主题里现存的一两天命中，量在可承受范围内。
	cfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	// 写进 ClickHouse 之后才手动提交。
	cfg.Consumer.Offsets.AutoCommit.Enable = false
	group, err := sarama.NewConsumerGroup(brokers, groupID, cfg)
	if err != nil {
		return fmt.Errorf("创建信号消费组失败: %w", err)
	}
	defer group.Close()
	go func() {
		for err := range group.Errors() {
			s.log.Warn("信号消费组错误", zap.Error(err))
		}
	}()
	backoff := time.Second
	for ctx.Err() == nil {
		if err := group.Consume(ctx, []string{topic}, s); err != nil && ctx.Err() == nil {
			s.log.Warn("信号消费出错，退避后重试", zap.Duration("backoff", backoff), zap.Error(err))
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
	}
	return nil
}

// Setup 每次分配分区后启动定期写入。
func (s *Sink) Setup(session sarama.ConsumerGroupSession) error {
	go func() {
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-session.Context().Done():
				return
			case <-t.C:
				s.flush(session)
			}
		}
	}()
	return nil
}

// Cleanup 分区被收回前把已合并的写掉，免得新的持有者从旧 offset 重放一遍。
func (s *Sink) Cleanup(session sarama.ConsumerGroupSession) error {
	s.flush(session)
	return nil
}

// ConsumeClaim 合并分到的分区里的命中。
func (s *Sink) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-session.Context().Done():
			return nil
		case msg, ok := <-claim.Messages():
			if !ok {
				return nil
			}
			// 内存满了先等写入腾出空间。暂停消费比丢弃好：积压留在 Kafka 里，修好了接着消费。
			for s.full() {
				select {
				case <-session.Context().Done():
					return nil
				case <-time.After(time.Second):
				}
			}
			s.add(msg)
			lag.WithLabelValues(fmt.Sprint(msg.Partition)).Set(float64(claim.HighWaterMarkOffset() - msg.Offset - 1))
		}
	}
}

func (s *Sink) full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows) >= maxKeys
}

// add 解析一条命中并并入合并表。解析不了的也要记 offset：它不该卡住后面的消息。
func (s *Sink) add(msg *sarama.ConsumerMessage) {
	r, result := parse(msg.Value)
	messagesTotal.WithLabelValues(result).Inc()
	s.mu.Lock()
	defer s.mu.Unlock()
	tp := topicPartition{topic: msg.Topic, partition: msg.Partition}
	if cur, ok := s.marks[tp]; !ok || msg.Offset > cur {
		s.marks[tp] = msg.Offset
	}
	if r != nil {
		s.mergeLocked(r)
	}
	pendingKeys.Set(float64(len(s.rows)))
}

func (s *Sink) mergeLocked(r *row) {
	k := key{bucket: r.Bucket.Unix(), host: r.HostID, stage: r.Stage, rule: r.RuleID, exe: r.Exe}
	cur := s.rows[k]
	if cur == nil && s.hostKeys[r.HostID] >= perHostMaxKeys {
		overflowTotal.Add(float64(r.Hits))
		r.Exe, r.ParentExe, r.Cmdline = overflowExe, "", ""
		k.exe = overflowExe
		cur = s.rows[k]
	}
	if cur == nil {
		s.rows[k] = r
		s.hostKeys[r.HostID]++
		return
	}
	cur.Hits += r.Hits
	if r.FirstSeen.Before(cur.FirstSeen) {
		cur.FirstSeen = r.FirstSeen
	}
	if r.LastSeen.After(cur.LastSeen) {
		cur.LastSeen = r.LastSeen
	}
}

// flush 把已合并的增量写入 ClickHouse，成功后提交对应的 offset；失败则放回内存，下次重试。
func (s *Sink) flush(session sarama.ConsumerGroupSession) {
	s.mu.Lock()
	rows, marks := s.rows, s.marks
	s.rows, s.marks, s.hostKeys = make(map[key]*row), make(map[topicPartition]int64), make(map[string]int)
	s.mu.Unlock()
	if len(rows) == 0 && len(marks) == 0 {
		return
	}
	batch := make([]*row, 0, len(rows))
	for _, r := range rows {
		batch = append(batch, r)
	}
	if len(batch) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), insertTimeout)
		err := s.insert(ctx, batch)
		cancel()
		if err != nil {
			writeFailuresTotal.Inc()
			s.log.Warn("信号写入 ClickHouse 失败，保留在内存里下次重试",
				zap.Int("rows", len(batch)), zap.Error(err))
			s.mu.Lock()
			for _, r := range batch {
				s.mergeLocked(r)
			}
			for tp, off := range marks {
				if cur, ok := s.marks[tp]; !ok || off > cur {
					s.marks[tp] = off
				}
			}
			pendingKeys.Set(float64(len(s.rows)))
			s.mu.Unlock()
			return
		}
		rowsWrittenTotal.Add(float64(len(batch)))
	}
	for tp, off := range marks {
		session.MarkOffset(tp.topic, tp.partition, off+1, "")
	}
	session.Commit()
	s.mu.Lock()
	pendingKeys.Set(float64(len(s.rows)))
	s.mu.Unlock()
}

func (s *Sink) insertCH(ctx context.Context, rows []*row) error {
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO signals")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := b.Append(r.Bucket, r.HostID, r.Stage, r.RuleID, r.RuleName, r.Severity, r.Technique,
			r.Tactic, r.Exe, r.ParentExe, r.Cmdline, r.Hits, r.FirstSeen, r.LastSeen); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

// parse 把一条 engine.alert 消息转成一行信号。返回的 result 用作指标标签。
func parse(value []byte) (*row, string) {
	var env envelope
	if err := json.Unmarshal(value, &env); err != nil {
		return nil, "decode_error"
	}
	if env.HostID == "" {
		return nil, "no_host"
	}
	at := env.DetectedAt
	if at.IsZero() {
		at = time.Now()
	}
	fields, ruleName := payloadFields(env.Payload)
	cmd := map[string]string{"cmdline": fields["cmdline"]}
	sanitize.Fields(cmd)
	return &row{
		Bucket:    at.Truncate(bucketSize),
		HostID:    clip(env.HostID),
		Stage:     clip(env.Stage),
		RuleID:    clip(ruleKey(env.Stage, env.RuleID)),
		RuleName:  clip(ruleName),
		Severity:  clip(env.Severity),
		Technique: clip(env.Technique),
		Tactic:    tacticOf(env),
		Exe:       clip(fields["exe"]),
		ParentExe: clip(fields["parent_exe"]),
		Cmdline:   clip(cmd["cmdline"]),
		Hits:      1,
		FirstSeen: at,
		LastSeen:  at,
	}, "ok"
}

// tacticOf 检测阶段自己声明了战术（TA####）时以它为准，否则由技术号推主战术。与 engine 风险累积的口径一致，
// 否则拿信号表对照风险判断时战术会对不上。
func tacticOf(env envelope) string {
	if strings.HasPrefix(env.Tactic, "TA") {
		return env.Tactic
	}
	return celengine.TacticFromTechnique(env.Technique)
}

// ruleKey 把消息里的规则号换成告警表里的写法：CEL 与攻击链的 rule_id 是纯数字，区分不了。
func ruleKey(stage, id string) string {
	switch stage {
	case "cel_rule":
		return "cel-" + id
	case "sequence":
		return "seq-" + id
	}
	return id
}

// payloadFields 从各阶段不同形态的载荷里取出事件字段与规则名：CEL 与攻击链放在
// matched_fields，部分硬编码检测放在 evidence，其余直接在顶层。
func payloadFields(raw json.RawMessage) (map[string]string, string) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, ""
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return out, ""
	}
	var ruleName string
	_ = json.Unmarshal(top["rule_name"], &ruleName)
	src := top
	for _, k := range []string{"matched_fields", "evidence", "fields"} {
		var inner map[string]json.RawMessage
		if v, ok := top[k]; ok && json.Unmarshal(v, &inner) == nil {
			src = inner
			break
		}
	}
	for _, k := range []string{"exe", "parent_exe", "cmdline"} {
		var v string
		if json.Unmarshal(src[k], &v) == nil {
			out[k] = v
		}
	}
	return out, ruleName
}

func clip(v string) string {
	v = strings.ToValidUTF8(v, "")
	if len(v) > fieldMaxLen {
		return strings.ToValidUTF8(v[:fieldMaxLen], "")
	}
	return v
}
