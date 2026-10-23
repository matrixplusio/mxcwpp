package writer

import (
	"strconv"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
)

// authEventsDDL 认证事件表。建表语句同时在 deploy/init-clickhouse.sql 里（新装），
// 这里的一份给已有的库在启动时补建。
//
// 按 (host_id, timestamp) 排序：最常见的查询是「这台主机这段时间谁登录过、谁执行了 sudo」。
// 来源地址与用户名另加跳数索引，支撑「这个地址登过哪些机器」这类跨主机查询。
const authEventsDDL = `CREATE TABLE IF NOT EXISTS auth_events (
	timestamp       DateTime64(3),
	host_id         String,
	hostname        String,
	event_type      LowCardinality(String),
	service         LowCardinality(String),
	trust           LowCardinality(String),
	username        String,
	target_user     String,
	source_ip       String,
	source_port     String,
	auth_method     LowCardinality(String),
	key_fingerprint String,
	reason          String,
	invalid_user    UInt8,
	tty             String,
	cwd             String,
	command         String,
	detail          String,
	pid             String,
	count           UInt32,
	raw             String,
	received_at     DateTime64(3) DEFAULT timestamp,
	INDEX idx_source_ip source_ip TYPE bloom_filter(0.01) GRANULARITY 4,
	INDEX idx_username username TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192`

// authEventsAddReceivedAt 给存量表补 received_at。
//
// timestamp 是主机自己报的发生时间，主机时钟可以被改；received_at 是 AgentCenter 收到这条记录的时间，
// 由服务端打上。两者对不上（相差远超正常的传输与补发延迟）本身就是线索。
//
// 默认值只给加列之前的旧行用（新行一律显式写入）。ALTER 加的列，旧数据分片在读取时才求默认值：
// 写 now64() 的话旧行每次读出来都是「此刻」，断流对账会以为那些主机刚发过心跳。退而用事件时间。
const authEventsAddReceivedAt = `ALTER TABLE auth_events ADD COLUMN IF NOT EXISTS received_at DateTime64(3) DEFAULT timestamp`

type authEventRow struct {
	Timestamp   time.Time
	HostID      string
	Hostname    string
	EventType   string
	Service     string
	Trust       string
	Username    string
	TargetUser  string
	SourceIP    string
	SourcePort  string
	AuthMethod  string
	KeyFP       string
	Reason      string
	InvalidUser uint8
	TTY         string
	Cwd         string
	Command     string
	Detail      string
	PID         string
	Count       uint32
	Raw         string
	ReceivedAt  time.Time
}

// authFieldMaxLen 单个文本字段入库的上限。字段内容来自主机，主机不可信。
const authFieldMaxLen = 2048

// WriteAuthEvent 把一条认证事件加入待写批次。
func (w *ClickHouseWriter) WriteAuthEvent(msg *kafka.MQMessage) error {
	if w.conn == nil {
		return nil
	}
	row, ok := parseAuthEvent(msg)
	if !ok {
		return nil
	}
	w.mu.Lock()
	w.waitRoomLocked()
	w.authRows = append(w.authRows, row)
	shouldFlush := len(w.authRows) >= w.batchSize
	w.mu.Unlock()
	if shouldFlush {
		select {
		case w.flushCh <- struct{}{}:
		default:
		}
	}
	return nil
}

// normalize 对已成行的数据重做解析时的截断与脱敏（回放转存数据时用）。
func (r *authEventRow) normalize() {
	clip := func(v string) string {
		if len(v) > authFieldMaxLen {
			return v[:authFieldMaxLen]
		}
		return v
	}
	for _, f := range []*string{&r.HostID, &r.Hostname, &r.EventType, &r.Service, &r.Trust, &r.Username,
		&r.TargetUser, &r.SourceIP, &r.SourcePort, &r.AuthMethod, &r.KeyFP, &r.Reason, &r.TTY, &r.Cwd,
		&r.Detail, &r.PID} {
		*f = clip(*f)
	}
	r.Command = sanitize.Cmdline(clip(r.Command))
	r.Raw = sanitize.Cmdline(clip(r.Raw))
	// 加列之前转存的数据没有接收时间。原始的接收时间已经找不回来，记成回放入库的时间，
	// 而不是零值（1970 年）——那会让按接收时间的查询把这些行漏掉。
	if r.ReceivedAt.IsZero() {
		r.ReceivedAt = time.Now()
	}
}

func parseAuthEvent(msg *kafka.MQMessage) (authEventRow, bool) {
	if len(msg.Body) == 0 {
		return authEventRow{}, false
	}
	fields, err := ParseRecordFields(msg.Body)
	if err != nil || fields["event_type"] == "" {
		return authEventRow{}, false
	}
	clip := func(k string) string {
		v := fields[k]
		if len(v) > authFieldMaxLen {
			return v[:authFieldMaxLen]
		}
		return v
	}
	row := authEventRow{
		Timestamp:  time.Now(),
		HostID:     msg.AgentID,
		Hostname:   msg.Hostname,
		EventType:  clip("event_type"),
		Service:    clip("service"),
		Trust:      clip("trust"),
		Username:   clip("username"),
		TargetUser: clip("target_user"),
		SourceIP:   clip("source_ip"),
		SourcePort: clip("source_port"),
		AuthMethod: clip("auth_method"),
		KeyFP:      clip("key_fingerprint"),
		Reason:     clip("reason"),
		TTY:        clip("tty"),
		Cwd:        clip("cwd"),
		// sudo 的命令行里可能带口令（mysql -pXXX 之类），入库前按命令行的规则脱敏。
		// raw 是同一行的原文，一并处理，否则脱敏等于没做。
		Command: sanitize.Cmdline(clip("command")),
		Detail:  clip("detail"),
		PID:     clip("pid"),
		Raw:     sanitize.Cmdline(clip("raw")),
		Count:   1,
		// AgentCenter 收到消息时打的时间；老消息没有就用 consumer 的处理时间。
		ReceivedAt: msg.ReceivedAt,
	}
	if row.ReceivedAt.IsZero() {
		row.ReceivedAt = time.Now()
	}
	if fields["invalid_user"] == "true" {
		row.InvalidUser = 1
	}
	if n, e := strconv.ParseUint(fields["count"], 10, 32); e == nil && n > 0 {
		row.Count = uint32(n)
	}
	// 事件自带的时间是它在主机上发生的时间；补发的事件到达时间会晚很多。
	if ts, e := strconv.ParseInt(fields["timestamp"], 10, 64); e == nil && ts > 0 {
		row.Timestamp = time.Unix(ts, 0)
	} else if msg.AgentTime > 0 {
		row.Timestamp = time.Unix(msg.AgentTime, 0)
	}
	return row, true
}

// flushAuthEvents 批量写入 auth_events 表。返回是否全部落盘成功。
func (w *ClickHouseWriter) flushAuthEvents(rows []authEventRow) (bool, map[int]bool) {
	return w.sendRows("auth_events",
		"INSERT INTO auth_events (timestamp, host_id, hostname, event_type, service, trust, username, target_user, source_ip, source_port, auth_method, key_fingerprint, reason, invalid_user, tty, cwd, command, detail, pid, count, raw, received_at)",
		len(rows), nil, func(batch chdriver.Batch, i int) error {
			r := rows[i]
			return rowErr(r.HostID, "", batch.Append(
				r.Timestamp, r.HostID, r.Hostname, r.EventType, r.Service, r.Trust,
				r.Username, r.TargetUser, r.SourceIP, r.SourcePort, r.AuthMethod, r.KeyFP,
				r.Reason, r.InvalidUser, r.TTY, r.Cwd, r.Command, r.Detail, r.PID, r.Count, r.Raw, r.ReceivedAt,
			))
		})
}
