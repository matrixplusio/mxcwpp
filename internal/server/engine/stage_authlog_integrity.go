package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// 认证日志采集的完整性检测。
//
// 认证事件本身回答不了「没有登录记录」是因为没人登录、采集停了、还是日志被人清过。
// logcollector 每 5 分钟发一条心跳，带 journald 的读取位置（序号组、序号、boot id）、
// 日志服务是否在跑，以及插件自己发现的异常；这里按主机记住上一条，比对出：
//   - 序号倒退或序号组变了（同一次开机内）：journal 被清空或替换；
//   - 来源从 journald 退到读文件，或磁盘上的 journal 目录没了；
//   - 日志服务进程没在跑；
//   - 插件报上来的：文件被原地截断、游标作废、读取卡住（已自愈）；
//   - 插件一小时内反复重启：可能有人在杀它。
//
// 「心跳停了」不在这里判断：engine 重启会丢掉内存状态，事件稀疏的主机也等不来触发判断的事件。
// 那件事由 manager 定时按 ClickHouse 里的心跳与主机在线状态对账（authlogsilence）。
//
// 心跳的到达顺序不可信：agent 断线期间的数据落盘，重连后与实时数据一起发，AC 写 Kafka 也有重试。
// 所以每条心跳带插件实例号与实例内递增的序号，过时的心跳不参与位置比对。不同实例之间按
// 服务端第一次见到的先后排序，不用心跳里的实例启动时间——那是主机时钟，回拨一下，
// 新实例就全被当成旧的，之后清 journal 也不会被比出来。

const (
	authlogHeartbeatKind = "auth_collector_heartbeat"

	// authlogStateTTL 这么久没有心跳的主机不再跟踪，防止状态表无限增长。
	authlogStateTTL   = 24 * time.Hour
	authlogPruneEvery = 10 * time.Minute
	// 一小时内换了这么多个插件实例就报：agent 自己重启、插件升级一小时里不会有这么多次。
	authlogRestartWindow = time.Hour
	authlogRestartLimit  = 4

	RuleAuthlogJournalRewind     = "AUTHLOG_JOURNAL_REWIND"
	RuleAuthlogSourceDowngrade   = "AUTHLOG_SOURCE_DOWNGRADE"
	RuleAuthlogFileTruncated     = "AUTHLOG_FILE_TRUNCATED"
	RuleAuthlogCursorReset       = "AUTHLOG_CURSOR_RESET"
	RuleAuthlogCollectorStalled  = "AUTHLOG_COLLECTOR_STALLED"
	RuleAuthlogLogdDown          = "AUTHLOG_LOGD_DOWN"
	RuleAuthlogCollectorRestarts = "AUTHLOG_COLLECTOR_RESTARTS"
	RuleAuthlogFileMissing       = "AUTHLOG_FILE_MISSING"
	RuleAuthlogProbeFailed       = "AUTHLOG_PROBE_FAILED"
	RuleAuthlogCursorSaveFailed  = "AUTHLOG_CURSOR_SAVE_FAILED"
	RuleAuthlogWriterMismatch    = "AUTHLOG_WRITER_MISMATCH"
	// authlogProbeFailLimit 连续这么多次心跳探不到 journald 头部就报：读取卡住的判断靠它，
	// 探不到时卡住检测就失效了（有人替换掉 journalctl 也是这个表现）。
	authlogProbeFailLimit = 3
	// authlogCursorSaveFailLimit 连续几次心跳写盘失败才报：偶发一次（临时文件被清掉之类）会自己恢复。
	authlogCursorSaveFailLimit = 2
	// RuleAuthlogCollectorSilent 由 manager 的定时对账产生，这里只登记规则号。
	RuleAuthlogCollectorSilent = "AUTHLOG_COLLECTOR_SILENT"
)

// authlogPos 一条心跳里的采集位置。
type authlogPos struct {
	Source     string `json:"source"`
	SeqnumID   string `json:"journal_seqnum_id,omitempty"`
	Seqnum     uint64 `json:"journal_seqnum,omitempty"`
	BootID     string `json:"journal_boot_id,omitempty"`
	Persistent string `json:"journal_persistent,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	hasSeqnum  bool
}

// authlogInstance 心跳出自哪个插件进程、是它的第几条。
type authlogInstance struct {
	id  string
	seq uint64
}

// 实例的取舍（见 onHeartbeat）：
//   - 每个实例记住最后的序号，序号没前进的心跳是同一实例里的重复或乱序，只留插件当场上报的告警；
//   - 别的实例要成为「当前实例」，得是刚启动的（头两条心跳），或者当前实例已经三个心跳周期没有心跳。
//
// 不按「谁先到」也不设退役名单：旧实例离线期间落盘的心跳会在新实例之后补发上来，engine 重启或
// 离线超过一天后也不知道谁新谁旧。退役名单一旦记错（当前实例的心跳晚到一会儿，就被补发上来的旧实例挤掉），
// 当前实例就再也回不来，之后的倒退一律被吞；按停顿时长接管则总会在三个周期内恢复。
const (
	authlogTakeoverMaxSeq = 2
	authlogTakeoverIdle   = 15 * time.Minute
	authlogSeenMax        = 32
	// authlogReplayLag 两条心跳的延迟相差这么多，就认为其中一条是补发的。正常的传输与批量发送在秒级。
	authlogReplayLag = 2 * time.Minute
)

type authlogSeen struct {
	seq uint64
	at  time.Time
}

type authlogHostState struct {
	lastBeat time.Time
	inst     authlogInstance
	// seen 见过的实例最后的序号与时间。
	seen       map[string]authlogSeen
	probeFails int
	saveFails  int
	// lag 当前实例最近一条心跳的延迟（Kafka 收到时间 − 主机时间），判断别的实例是不是补发用。
	lag    time.Duration
	hasLag bool
	pos    authlogPos
	// starts 最近一小时内出现过的新实例的时间。
	starts          []time.Time
	restartsFiredAt time.Time
}

// AuthlogIntegrityStage 见文件头。
type AuthlogIntegrityStage struct {
	logger *zap.Logger

	mu        sync.Mutex
	hosts     map[string]*authlogHostState
	lastPrune time.Time
}

// NewAuthlogIntegrityStage 构造。
func NewAuthlogIntegrityStage(logger *zap.Logger) *AuthlogIntegrityStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AuthlogIntegrityStage{logger: logger, hosts: make(map[string]*authlogHostState)}
}

// Name 满足 Stage interface。
func (s *AuthlogIntegrityStage) Name() string { return "authlog_integrity" }

// Process 只看采集心跳；其它事件直接返回，不加锁。
func (s *AuthlogIntegrityStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType != DataTypeAuthEvent {
		return nil, nil
	}
	f, err := ev.Fields()
	if err != nil || f["event_type"] != authlogHeartbeatKind {
		return nil, nil
	}
	hostID := ev.HostID
	if hostID == "" {
		hostID = ev.AgentID
	}
	if hostID == "" {
		return nil, nil
	}
	at := ev.EventTime
	if at.IsZero() {
		at = ev.ReceivedAt
	}
	if at.IsZero() {
		at = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(at)
	st := s.hosts[hostID]
	if st == nil {
		st = &authlogHostState{}
		s.hosts[hostID] = st
	}
	return s.onHeartbeat(ev, hostID, st, f, at), nil
}

func (s *AuthlogIntegrityStage) onHeartbeat(ev PipelineEvent, hostID string, st *authlogHostState, f map[string]string, at time.Time) []Alert {
	reasons := map[string]bool{}
	for _, r := range strings.Split(f["reason"], ",") {
		reasons[strings.TrimSpace(r)] = true
	}
	inst := authlogInstance{id: f["instance_id"]}
	inst.seq, _ = strconv.ParseUint(f["hb_seq"], 10, 64)
	raw := parseAuthlogPos(f)

	var alerts []Alert
	// 插件当场发现的异常：不管这条心跳是不是过时的，事情都真实发生过。
	if reasons["file_truncated"] {
		// 用 copytruncate 轮转的 logrotate 也会这样，所以是 medium；清痕迹的人同样会这么做。
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogFileTruncated, "medium", "T1070.002",
			fmt.Sprintf("认证日志文件 %s 被原地截断（inode 不变、内容变短）", raw.FilePath), st.pos, raw))
	}
	if reasons["cursor_reset"] {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogCursorReset, "medium", "T1070.002",
			"journalctl 拒绝了插件保存的读取位置，插件已从当前位置重新开始：上次位置之后的一段日志不会再被读到", st.pos, raw))
	}
	if reasons["stalled"] {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogCollectorStalled, "medium", "T1562.001",
			"journald 有新的认证记录，插件的读取位置却两个心跳周期没动（journalctl 被冻住或卡死）；插件已重启 journalctl 并从保存的位置补读", st.pos, raw))
	}
	if f["logd_alive"] == "false" {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogLogdDown, "high", "T1562.001",
			fmt.Sprintf("主机上的日志服务进程没有在运行（来源 %s）：此后的登录、sudo 都不会留下记录", raw.Source), st.pos, raw))
	}

	// 一条心跳的「延迟」= Kafka 收到的时间 − 主机报的时间。实时心跳的延迟只是这台主机的时钟偏差；
	// 断线期间落盘、重连后补发的心跳延迟会大得多。只拿它和当前实例最近一条心跳的延迟比，不和固定阈值比：
	// 主机时钟整体偏了（自然漂移或被回拨）两边一起偏，抵消掉，不会把所有心跳都当成补发。
	lag, hasLag := time.Duration(0), false
	if ts, err := strconv.ParseInt(f["timestamp"], 10, 64); err == nil && ts > 0 {
		lag, hasLag = at.Sub(time.Unix(ts, 0)), true
	}

	// 过时的心跳不参与位置比对，否则补发的旧心跳会被当成「序号倒退」。
	if inst.id != "" {
		seen, known := st.seen[inst.id]
		if known && inst.seq <= seen.seq {
			return alerts
		}
		st.noteSeen(inst, at)
		// 没见过的实例的头两条心跳就是一次重启，补发上来的也是真实发生过的重启。
		if !known && inst.seq <= authlogTakeoverMaxSeq {
			if a, ok := s.noteStartLocked(ev, hostID, st, at, raw); ok {
				alerts = append(alerts, a)
			}
		}
		alerts = append(alerts, s.stateAlertsLocked(ev, hostID, st, f, raw)...)
		if inst.id != st.inst.id && st.inst.id != "" && !st.takesOver(inst, lag, hasLag, at) {
			return alerts
		}
	} else {
		alerts = append(alerts, s.stateAlertsLocked(ev, hostID, st, f, raw)...)
	}
	if hasLag {
		st.lag, st.hasLag = lag, true
	}

	prev := st.pos
	hadPrev := !st.lastBeat.IsZero()
	cur := mergeAuthlogPos(prev, raw)
	// lastBeat 记 Kafka 收到的时间，和接管判断里的 at 同一个钟。
	st.lastBeat, st.inst, st.pos = at, inst, cur
	if !hadPrev {
		return alerts
	}

	if prev.Source == "journal" && cur.Source != "journal" {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogSourceDowngrade, "medium", "T1562.001",
			fmt.Sprintf("认证日志来源从 journald 退到 %s：journald 不可用后，事件不再能校验写入进程的身份", cur.Source), prev, cur))
	} else if prev.Source == "journal" && cur.Source == "journal" && prev.BootID != "" && prev.BootID == cur.BootID &&
		prev.Persistent == "true" && cur.Persistent == "false" {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogSourceDowngrade, "medium", "T1562.001",
			"同一次开机内 /var/log/journal 消失了：journald 改写内存，重启后认证日志全部丢失", prev, cur))
	}

	// 序号只在同一次开机内比较。跨重启时 journal 若不落盘（没有 /var/log/journal），
	// 序号组本来就会换；落盘的情况下 journald 启动早期写内存的那段怎么编号，各版本不一，
	// 拿不准就不判——重启前后删日志由 EDR 的文件删除规则覆盖。
	// journald 在运行中发现当前文件损坏时也会换组，概率很低，出现时值得人看一眼。
	if prev.hasSeqnum && raw.hasSeqnum && prev.BootID != "" && prev.BootID == cur.BootID {
		switch {
		case prev.SeqnumID != cur.SeqnumID:
			alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogJournalRewind, "high", "T1070.002",
				"同一次开机内 journald 的序号组变了：日志文件被整体删除或替换后 journald 才会换一组新序号", prev, cur))
		case cur.Seqnum < prev.Seqnum:
			alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogJournalRewind, "high", "T1070.002",
				fmt.Sprintf("同一次开机内 journald 的读取序号从 %d 倒退到 %d：已读过的日志被替换", prev.Seqnum, cur.Seqnum), prev, cur))
		}
	}
	return alerts
}

// takesOver 非当前实例的这条心跳能否接管为当前实例。
func (st *authlogHostState) takesOver(inst authlogInstance, lag time.Duration, hasLag bool, at time.Time) bool {
	if hasLag && st.hasLag {
		switch {
		case lag < st.lag-authlogReplayLag:
			// 它比当前实例「新」得多：当前实例的心跳才是在补发旧数据（engine 重启后补发的先到）。
			return true
		case lag > st.lag+authlogReplayLag:
			// 它是补发上来的旧心跳：不能以刚启动的身份接管，否则刚重启就断线的旧实例会报一次假倒退。
			return at.Sub(st.lastBeat) >= authlogTakeoverIdle
		}
	}
	return inst.seq <= authlogTakeoverMaxSeq || at.Sub(st.lastBeat) >= authlogTakeoverIdle
}

// stateAlertsLocked 心跳里报的主机当前状态：文件缺失、写入方不一致、探测失败。
// 放在接管判断之前：新实例还没接管的那段时间里，它报上来的状态同样是真的。
func (s *AuthlogIntegrityStage) stateAlertsLocked(ev PipelineEvent, hostID string, st *authlogHostState, f map[string]string, raw authlogPos) []Alert {
	var alerts []Alert
	if f["file_missing"] == "true" {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogFileMissing, "high", "T1070.002",
			fmt.Sprintf("认证日志文件 %s 不存在：被删除或改名后没有重建，此后的登录记录无处可读", raw.FilePath), st.pos, raw))
	}
	if f["writer_inode_mismatch"] == "true" {
		alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogWriterMismatch, "medium", "T1070.002",
			fmt.Sprintf("日志服务正写着与 %s 同名前缀的另一个文件，而不是插件在读的这个：文件可能被改名后换成了一个空的同名文件（也可能是轮转后日志服务没有重开文件），此后的认证记录读不到", raw.FilePath),
			st.pos, raw))
	}
	if f["head_probe_error"] == "true" {
		st.probeFails++
		if st.probeFails == authlogProbeFailLimit {
			alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogProbeFailed, "medium", "T1562.001",
				fmt.Sprintf("连续 %d 次心跳都探不到 journald 的最新位置，读取卡住的检测因此失效（journalctl 被替换或损坏也是这个表现）", authlogProbeFailLimit),
				st.pos, raw))
		}
	} else {
		st.probeFails = 0
	}
	// 读取位置写不进盘时，插件上报的位置停在旧处：最后读到的那段日志被替换，倒退检测比不出来。
	if f["cursor_save_failed"] == "true" {
		st.saveFails++
		if st.saveFails == authlogCursorSaveFailLimit {
			alerts = append(alerts, authlogAlert(ev, hostID, RuleAuthlogCursorSaveFailed, "medium", "T1562.001",
				fmt.Sprintf("连续 %d 次心跳都没能把读取位置写盘（常见原因是磁盘满）：这段时间里最近读过的日志被替换，倒退检测发现不了", authlogCursorSaveFailLimit),
				st.pos, raw))
		}
	} else {
		st.saveFails = 0
	}
	return alerts
}

// noteSeen 记下实例最后的序号；超过上限时忘掉最久没出现的那个。
// 没带实例号的心跳（老版本插件）不经过这里，按到达顺序处理。
func (st *authlogHostState) noteSeen(inst authlogInstance, at time.Time) {
	if st.seen == nil {
		st.seen = map[string]authlogSeen{}
	}
	st.seen[inst.id] = authlogSeen{seq: inst.seq, at: at}
	if len(st.seen) <= authlogSeenMax {
		return
	}
	var oldest string
	for id, v := range st.seen {
		if oldest == "" || v.at.Before(st.seen[oldest].at) {
			oldest = id
		}
	}
	delete(st.seen, oldest)
}

// noteStartLocked 记一次新实例；一小时内超过上限报一次。
func (s *AuthlogIntegrityStage) noteStartLocked(ev PipelineEvent, hostID string, st *authlogHostState, at time.Time, cur authlogPos) (Alert, bool) {
	cutoff := at.Add(-authlogRestartWindow)
	kept := st.starts[:0]
	for _, t := range st.starts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.starts = append(kept, at)
	if len(st.starts) < authlogRestartLimit || at.Sub(st.restartsFiredAt) < authlogRestartWindow {
		return Alert{}, false
	}
	st.restartsFiredAt = at
	return authlogAlert(ev, hostID, RuleAuthlogCollectorRestarts, "medium", "T1562.001",
		fmt.Sprintf("认证日志采集插件一小时内重启了 %d 次：可能有人反复杀掉或冻住它，每次重启之间的空档里采集是停的", len(st.starts)),
		st.pos, cur), true
}

// mergeAuthlogPos 心跳里没带的位置字段沿用上一次的：插件刚重启、还没读到记录时心跳不带序号，
// 直接覆盖会把基线清空，接下来的倒退就无从比较。
func mergeAuthlogPos(prev, cur authlogPos) authlogPos {
	if cur.Source != prev.Source {
		return cur
	}
	if !cur.hasSeqnum && prev.hasSeqnum {
		cur.SeqnumID, cur.Seqnum, cur.hasSeqnum = prev.SeqnumID, prev.Seqnum, true
		if cur.BootID == "" {
			cur.BootID = prev.BootID
		}
	}
	return cur
}

func parseAuthlogPos(f map[string]string) authlogPos {
	p := authlogPos{
		Source:     f["source"],
		SeqnumID:   f["journal_seqnum_id"],
		BootID:     f["journal_boot_id"],
		Persistent: f["journal_persistent"],
		FilePath:   f["file_path"],
	}
	if n, err := strconv.ParseUint(f["journal_seqnum"], 10, 64); err == nil && p.SeqnumID != "" {
		p.Seqnum, p.hasSeqnum = n, true
	}
	return p
}

func (s *AuthlogIntegrityStage) pruneLocked(now time.Time) {
	if now.Sub(s.lastPrune) < authlogPruneEvery {
		return
	}
	s.lastPrune = now
	for h, st := range s.hosts {
		if now.Sub(st.lastBeat) > authlogStateTTL {
			delete(s.hosts, h)
		}
	}
}

func authlogAlert(ev PipelineEvent, hostID, ruleID, severity, technique, reason string, prev, cur authlogPos) Alert {
	payload, _ := json.Marshal(map[string]any{
		"would_action": map[string]string{"reason": reason},
		"previous":     prev,
		"current":      cur,
	})
	return Alert{
		AlertID:        fmt.Sprintf("alrt-authlog-%s-%s-%d-%d", ruleID, hostID, ev.Partition, ev.Offset),
		RuleID:         ruleID,
		Severity:       severity,
		ATTCKTactic:    "TA0005", // Defense Evasion
		ATTCKTechnique: technique,
		Payload:        payload,
		WouldAction:    payload,
	}
}

var _ Stage = (*AuthlogIntegrityStage)(nil)
