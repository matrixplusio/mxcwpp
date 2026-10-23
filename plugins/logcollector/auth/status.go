package auth

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 心跳让服务端能分清三件事：采集在跑但没人登录、采集停了、日志被人动过。
// 只看认证事件分不出来——三种情况在服务端看都是「这台机器没有新的登录记录」。

const (
	// HeartbeatInterval 心跳间隔。服务端按它的几倍判断断流，改这里要同步改服务端的阈值。
	HeartbeatInterval = 5 * time.Minute

	SourceJournal = "journal"
	SourceFile    = "file"
	SourceNone    = "none"

	// 心跳的触发原因。除 periodic 外都是立即发出的；同时有几个时用逗号连起来。
	HeartbeatStart         = "start"
	HeartbeatPeriodic      = "periodic"
	HeartbeatSourceChanged = "source_changed"
	HeartbeatFileTruncated = "file_truncated"
	HeartbeatCursorReset   = "cursor_reset"
	// HeartbeatStalled journald 里有新记录，读取位置却两个心跳周期没动：journalctl 被冻住或卡死。
	// 插件已把它杀掉重启（从保存的位置接着读，不丢），这条心跳是告诉服务端发生过。
	HeartbeatStalled = "stalled"
)

// journalPersistentDir 存在时 journald 把日志写在磁盘上，重启后序号接着走；
// 不存在时日志在内存里，重启即清空、序号从新的一组开始——服务端要据此区分「重启」和「被清」。
const journalPersistentDir = "/var/log/journal"

// 日志服务进程：进程名（/proc/<pid>/comm，内核截到 15 个字符）对上、程序也在标准位置才算。
// 只看进程名的话，把 sleep 软链成 rsyslogd 跑起来，「日志服务在跑」「写的就是这个文件」就都能糊弄过去。
var (
	journaldComms = map[string][]string{
		"systemd-journal": {"/usr/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"},
	}
	syslogComms = map[string][]string{
		"rsyslogd":  {"/usr/sbin/rsyslogd", "/sbin/rsyslogd"},
		"syslog-ng": {"/usr/sbin/syslog-ng", "/sbin/syslog-ng"},
		"syslogd":   {"/sbin/syslogd", "/usr/sbin/syslogd", "/bin/busybox"},
	}
)

// journalPos journald 游标里与「位置」有关的三项。
type journalPos struct {
	SeqnumID string // 序号所属的组；日志被整体清掉后 journald 换一组新的
	Seqnum   uint64 // 组内单调递增
	BootID   string
}

// parseJournalCursor 从游标（s=…;i=…;b=…;m=…;t=…;x=…）取出位置。
func parseJournalCursor(c string) (journalPos, bool) {
	var p journalPos
	var haveSeq bool
	for _, kv := range strings.Split(c, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "s":
			p.SeqnumID = v
		case "i":
			n, err := strconv.ParseUint(v, 16, 64)
			if err != nil {
				return journalPos{}, false
			}
			p.Seqnum, haveSeq = n, true
		case "b":
			p.BootID = v
		}
	}
	return p, haveSeq && p.SeqnumID != ""
}

// sourceStatus 采集来源的当前位置与计数。来源协程写，心跳协程读。
type sourceStatus struct {
	// instanceID 每个插件进程一个。服务端用它加 hbSeq 认出乱序到达的旧心跳
	// （agent 断线期间的数据落盘，重连后与实时数据一起发，先后不定）。
	instanceID      string
	instanceStarted time.Time

	mu      sync.Mutex
	hbSeq   uint64
	source  string
	journal journalPos
	// saved 已写进游标文件的位置，心跳上报的是它而不是 journal。插件重启后从游标文件续读，
	// 报「读到哪」的话，两次写盘之间被停掉会重读几条，服务端看到的就是序号倒退、判成日志被替换。
	// 心跳前先 flushCursor，让 saved 追上 journal：否则安静的主机上最后读到的几条可能一直不写盘，
	// 那一段被替换后服务端比不出倒退。
	saved journalPos
	// lastCursor / savedCursor 是 journal / saved 对应的原始游标；cursorPath 由来源协程设置。
	lastCursor, savedCursor, cursorPath string
	// saveFailed 自上次心跳以来有游标写盘失败（比如根盘满了），要在心跳里报出来。
	saveFailed bool
	// saveMu 串行化游标写盘：来源协程与心跳协程都会写，同一个临时文件不能并发。
	saveMu sync.Mutex
	file   fileState
	// fileMissing 读文件来源时，最近一次轮询发现认证日志文件不存在。
	fileMissing bool
	// stop 结束当前的 journalctl（读取卡住时用）；没有在跑时为 nil。
	stop func()
	// 自上次心跳以来的计数。
	read, rejected uint64
}

func newSourceStatus() *sourceStatus {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &sourceStatus{source: SourceNone, instanceID: hex.EncodeToString(b), instanceStarted: time.Now()}
}

// setSource 切换来源，返回是否真的变了。
func (s *sourceStatus) setSource(src string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source == src {
		return false
	}
	s.source = src
	return true
}

// seedJournal 用上次保存的游标作为起始位置。不这样做的话，插件重启后的心跳在读到下一条记录前
// 都不带位置，服务端就没有基线可比：先杀插件、再清 journal，倒退就看不出来了。
func (s *sourceStatus) seedJournal(cursor string) {
	if p, ok := parseJournalCursor(cursor); ok {
		s.mu.Lock()
		s.journal, s.saved = p, p
		s.lastCursor, s.savedCursor = cursor, cursor
		s.mu.Unlock()
	}
}

func (s *sourceStatus) setCursorPath(path string) {
	s.mu.Lock()
	s.cursorPath = path
	s.mu.Unlock()
}

// saveCursor 把游标写盘，成功后心跳才上报这个位置。
func (s *sourceStatus) saveCursor(cursor string) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	path := s.cursorPath
	s.mu.Unlock()
	if path == "" || cursor == "" || s.staleCursor(cursor) {
		return
	}
	ok := writeCursor(path, cursor)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.saveFailed = true
		return
	}
	if p, ok := parseJournalCursor(cursor); ok {
		s.saved, s.savedCursor = p, cursor
	}
}

// staleCursor 同一序号组里不比已写盘的新：心跳前的刷盘与读取协程交错时，较旧的游标可能后到，
// 写下去会让文件里的位置倒退、重启后重读。
func (s *sourceStatus) staleCursor(cursor string) bool {
	p, ok := parseJournalCursor(cursor)
	s.mu.Lock()
	defer s.mu.Unlock()
	return ok && s.saved.SeqnumID != "" && p.SeqnumID == s.saved.SeqnumID && p.Seqnum <= s.saved.Seqnum
}

// flushCursor 把读到但还没写盘的游标写盘。心跳前调用。
func (s *sourceStatus) flushCursor() {
	s.mu.Lock()
	c, pending := s.lastCursor, s.lastCursor != s.savedCursor
	s.mu.Unlock()
	if pending {
		s.saveCursor(c)
	}
}

func (s *sourceStatus) noteJournalCursor(cursor string) {
	p, ok := parseJournalCursor(cursor)
	s.mu.Lock()
	s.read++
	if ok {
		s.journal, s.lastCursor = p, cursor
	}
	s.mu.Unlock()
}

func (s *sourceStatus) noteRejected() {
	s.mu.Lock()
	s.rejected++
	s.mu.Unlock()
}

func (s *sourceStatus) noteFile(st fileState, lines uint64, missing bool) {
	s.mu.Lock()
	s.file = st
	s.read += lines
	s.fileMissing = missing
	s.mu.Unlock()
}

func (s *sourceStatus) setStopper(stop func()) {
	s.mu.Lock()
	s.stop = stop
	s.mu.Unlock()
}

// stopJournal 结束正在跑的 journalctl，来源协程会从保存的位置重新拉起它。
func (s *sourceStatus) stopJournal() {
	s.mu.Lock()
	stop := s.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
}

func (s *sourceStatus) fileSnapshot() fileState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file
}

func (s *sourceStatus) snapshot() (source string, pos journalPos) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.source, s.journal
}

// heartbeatProbe 心跳时现场探测的结果。
type heartbeatProbe struct {
	head    journalPos // 同一组进程名过滤下 journald 里最新的一条；SeqnumID 为空表示没探到
	headErr bool       // 探测 journald 头部失败：读取卡住的检测这一轮失效，要让服务端看得到
	// writerMismatch 日志服务写的不是插件在读的那个文件（读文件来源）。
	writerMismatch bool
	logdAlive      *bool // 日志服务进程是否在跑；nil 表示不适用
}

// heartbeat 生成一条心跳事件并清零计数。
func (s *sourceStatus) heartbeat(reasons []string, probe heartbeatProbe, now time.Time) *Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hbSeq++
	f := map[string]string{
		"source":           s.source,
		"read":             strconv.FormatUint(s.read, 10),
		"rejected":         strconv.FormatUint(s.rejected, 10),
		"instance_id":      s.instanceID,
		"instance_started": strconv.FormatInt(s.instanceStarted.Unix(), 10),
		"hb_seq":           strconv.FormatUint(s.hbSeq, 10),
	}
	s.read, s.rejected = 0, 0
	if s.saveFailed {
		f["cursor_save_failed"] = "true"
		s.saveFailed = false
	}
	if probe.logdAlive != nil {
		f["logd_alive"] = strconv.FormatBool(*probe.logdAlive)
	}
	switch s.source {
	case SourceJournal:
		f["journal_persistent"] = strconv.FormatBool(dirExists(journalPersistentDir))
		if s.saved.SeqnumID != "" {
			f["journal_seqnum_id"] = s.saved.SeqnumID
			f["journal_seqnum"] = strconv.FormatUint(s.saved.Seqnum, 10)
			f["journal_boot_id"] = s.saved.BootID
		}
		if probe.headErr {
			f["head_probe_error"] = "true"
		}
		if probe.head.SeqnumID != "" {
			f["journal_head_seqnum_id"] = probe.head.SeqnumID
			f["journal_head_seqnum"] = strconv.FormatUint(probe.head.Seqnum, 10)
		}
	case SourceFile:
		f["file_path"] = s.file.Path
		f["file_inode"] = strconv.FormatUint(s.file.Inode, 10)
		f["file_offset"] = strconv.FormatInt(s.file.Offset, 10)
		if probe.writerMismatch {
			f["writer_inode_mismatch"] = "true"
		}
		if s.fileMissing {
			// 文件被删或被改名走、又没重建时，读取只是静静地失败，位置不动、日志服务照常在跑。
			f["file_missing"] = "true"
		}
	}
	ev := &Event{Kind: KindHeartbeat, Time: now, Service: "logcollector", Trust: s.trustLocked(),
		Reason: strings.Join(reasons, ","), Count: 1, Extra: f}
	// 给看登录审计页面的人一个能读的摘要；服务端用的是上面的结构化字段。
	ev.Detail = heartbeatSummary(f)
	return ev
}

func (s *sourceStatus) trustLocked() string {
	if s.source == SourceFile {
		return TrustFile
	}
	return TrustJournal
}

func heartbeatSummary(f map[string]string) string {
	parts := []string{"source=" + f["source"], "read=" + f["read"], "rejected=" + f["rejected"]}
	for _, k := range []string{"logd_alive", "journal_seqnum_id", "journal_seqnum", "journal_head_seqnum", "journal_boot_id",
		"journal_persistent", "cursor_save_failed", "file_path", "file_inode", "file_offset"} {
		if v, ok := f[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// logdPIDs 扫 /proc 找日志服务进程。ok 为 false 表示 /proc 读不了，判断不了。
func logdPIDs(procRoot string, procs map[string][]string) (pids []string, ok bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(procRoot + "/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		exes, known := procs[strings.TrimSpace(string(b))]
		if !known {
			continue
		}
		exe, err := os.Readlink(procRoot + "/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		// 程序文件被软件包升级替换、进程还没重启时，链接后面带 " (deleted)"。
		if containsString(exes, strings.TrimSuffix(exe, " (deleted)")) {
			pids = append(pids, e.Name())
		}
	}
	return pids, true
}

// processRunning 有没有日志服务进程在跑。日志服务被停掉时 journald / 日志文件都不再有新记录，
// 读取位置自然不动，单看位置分不出「没人登录」与「日志服务没了」。
func processRunning(procRoot string, procs map[string][]string) bool {
	pids, ok := logdPIDs(procRoot, procs)
	// 读不了 /proc 就当在跑：这一项报不出来，不能因此报「日志服务停了」。
	return !ok || len(pids) > 0
}

// writerMismatch 日志服务是不是正写着同名前缀的另一个文件（secure-20261022 之类）而不是插件在读的这个：
// 旧文件被改名、换上了空的同名文件，就是这个样子。
//
// 不看「有没有进程打开着插件在读的文件」：另起一个真正的 rsyslogd 打开新文件就能满足它；
// 而 rsyslog 收到轮转后的 HUP 会关掉所有文件、等下一条日志才重开，安静的主机上它手里本来就没有这个文件。
// 找不到日志服务进程、或读不了它们的 fd 时返回 false：判断不了就不报。
func writerMismatch(procRoot string, procs map[string][]string, path string, inode uint64) bool {
	pids, ok := logdPIDs(procRoot, procs)
	if !ok {
		return false
	}
	base := filepath.Base(path)
	for _, pid := range pids {
		fdDir := procRoot + "/" + pid + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			fi, err := os.Stat(fdDir + "/" + fd.Name())
			if err != nil || inodeOf(fi) == inode {
				continue
			}
			if target, err := os.Readlink(fdDir + "/" + fd.Name()); err == nil &&
				strings.HasPrefix(filepath.Base(strings.TrimSuffix(target, " (deleted)")), base) {
				return true
			}
		}
	}
	return false
}

// reasonSet 待发的即时心跳原因。合并而不是丢弃：截断、游标作废这类原因丢一条就是漏报一次。
type reasonSet struct {
	mu  sync.Mutex
	set map[string]bool
}

func (r *reasonSet) add(reason string) {
	r.mu.Lock()
	if r.set == nil {
		r.set = map[string]bool{}
	}
	r.set[reason] = true
	r.mu.Unlock()
}

func (r *reasonSet) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.set))
	for k := range r.set {
		out = append(out, k)
	}
	r.set = nil
	sort.Strings(out)
	return out
}
