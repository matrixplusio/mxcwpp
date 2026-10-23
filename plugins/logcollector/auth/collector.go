package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DefaultStateDir 插件保存读取位置的目录。
const DefaultStateDir = "/var/lib/mxcwpp/logcollector"

const (
	flushInterval       = 2 * time.Second
	restartBackoffMin   = 5 * time.Second
	restartBackoffMax   = 2 * time.Minute
	rejectedLogInterval = 10 * time.Minute
)

// Collector 读取认证日志、解析、合并限速后交给 send。
type Collector struct {
	logger   *zap.Logger
	stateDir string
	send     func(*Event)
	co       *coalescer
	status   *sourceStatus
	pending  reasonSet
	notifyCh chan struct{}
	// procRoot 检查日志服务进程用，测试里换成假目录。
	procRoot string
	// stuckRead 上一次心跳时「头部比已读位置新」的已读位置；隔了一个心跳周期还是它就判定读取卡住。
	stuckRead *journalPos
	stuckAt   time.Time
	// writerMisses 连续几次心跳日志服务都没有打开插件正在读的文件。
	writerMisses int

	mu       sync.Mutex
	rejected map[string]int // 进程名对得上、但程序路径或身份不符的记录数
}

// NewCollector 构造采集器。send 在采集协程里被调用，不能长时间阻塞。
func NewCollector(logger *zap.Logger, stateDir string, send func(*Event)) *Collector {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return &Collector{logger: logger, stateDir: stateDir, send: send, co: newCoalescer(), rejected: make(map[string]int),
		status: newSourceStatus(), notifyCh: make(chan struct{}, 1), procRoot: "/proc"}
}

// Run 采集直到 ctx 结束。来源出错时退避重试，不退出——插件退出会被 agent 当成崩溃反复拉起。
func (c *Collector) Run(ctx context.Context) {
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		c.logger.Error("创建状态目录失败，读取位置将无法保存", zap.String("dir", c.stateDir), zap.Error(err))
	}
	c.status.seedJournal(readCursor(filepath.Join(c.stateDir, journalCursorFile)))
	go c.flushLoop(ctx)

	backoff := restartBackoffMin
	for ctx.Err() == nil {
		started := time.Now()
		err := c.runSource(ctx)
		if ctx.Err() != nil {
			return
		}
		// 跑了一阵才出错，说明来源本身是好的，退避从头算。
		if time.Since(started) > restartBackoffMax {
			backoff = restartBackoffMin
		}
		c.logger.Warn("认证日志来源中断，稍后重试", zap.Error(err), zap.Duration("retry_in", backoff))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > restartBackoffMax {
			backoff = restartBackoffMax
		}
	}
}

func (c *Collector) runSource(ctx context.Context) error {
	err := runJournal(ctx, c.stateDir, c.handle, c.noteRejected, c.status, c.notify)
	if !errors.Is(err, ErrJournalUnavailable) {
		return err
	}
	c.logger.Warn("本机没有 journalctl，改读认证日志文件；这类事件无法确认写入进程的身份")
	err = runFile(ctx, c.stateDir, c.handle, c.status, c.notify)
	if errors.Is(err, ErrNoLogSource) {
		c.status.setSource(SourceNone)
	}
	return err
}

func (c *Collector) handle(en Entry) {
	ev := Parse(en)
	if ev == nil {
		return
	}
	for _, out := range c.co.Offer(ev, time.Now()) {
		c.send(out)
	}
}

func (c *Collector) noteRejected(comm, exe, uid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rejected) < 64 {
		c.rejected[comm+" exe="+exe+" uid="+uid]++
	}
}

// notify 请求立即发一次心跳。原因先记下再唤醒：唤醒信号只留一个，原因一个不丢。
func (c *Collector) notify(reason string) {
	c.pending.add(reason)
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}
}

// sendHeartbeat 心跳不经过合并与限速：它是判断「采集停了」的唯一依据，不能被认证事件的洪泛挤掉。
func (c *Collector) sendHeartbeat(ctx context.Context, reasons []string, now time.Time) {
	c.status.flushCursor()
	probe := c.probe(ctx)
	if c.checkStalled(probe.head, now) {
		reasons = append(reasons, HeartbeatStalled)
		c.logger.Warn("journald 有新记录但读取位置两个心跳周期没动，重启 journalctl")
		c.status.stopJournal()
	}
	c.send(c.status.heartbeat(reasons, probe, now))
}

// probe 心跳时现场检查：journald 的头部位置、日志服务是否在跑。
func (c *Collector) probe(ctx context.Context) heartbeatProbe {
	var p heartbeatProbe
	source, read := c.status.snapshot()
	var names map[string][]string
	switch source {
	case SourceJournal:
		names = journaldComms
		head, err := journalHead(ctx, true)
		switch {
		case err != nil:
			// 包括 journalctl 不见了：来源是 journald 时它不该消失，删掉它正是让卡住检测失效的办法。
			p.headErr = true
		case head.SeqnumID == "" && read.SeqnumID != "":
			// 读到过记录，按进程名过滤却一条都没有。安静的主机上旧记录被 journald 按容量清掉是正常的；
			// 探测用的 journalctl 被换成什么都不输出的东西则不是。不加过滤再取一条：journal 里有东西
			// 就说明 journalctl 是好的，只是认证记录老化了。
			if whole, err := journalHead(ctx, false); err != nil || whole.SeqnumID == "" {
				p.headErr = true
			}
		default:
			p.head = head
		}
	case SourceFile:
		names = syslogComms
	}
	if names != nil {
		alive := processRunning(c.procRoot, names)
		p.logdAlive = &alive
		if source == SourceFile && alive {
			p.writerMismatch = c.checkWriterInode()
		}
	}
	return p
}

// checkWriterInode 日志服务打开的文件里没有插件正在读的那个，连续两次心跳才报。
//
// 把认证日志改名成轮转的样子、再 touch 一个同名空文件：改名规则当它是轮转，文件也没有缺失，
// 插件读着一个永远是空的新文件，日志服务还在往改了名的旧文件里写。看「写的人」和「读的人」
// 是不是同一个文件才能发现（logrotate 配置漏了通知日志服务重开文件，也是同样的后果）。
func (c *Collector) checkWriterInode() bool {
	st := c.status.fileSnapshot()
	if st.Inode == 0 {
		return false
	}
	if !writerMismatch(c.procRoot, syslogComms, st.Path, st.Inode) {
		c.writerMisses = 0
		return false
	}
	c.writerMisses++
	return c.writerMisses >= 2
}

// stallMinGap 两次「落后」至少隔这么久才算卡住。即时心跳（来源切换、游标作废）可能一秒内连发两条，
// 那时读取位置还没来得及动。
const stallMinGap = HeartbeatInterval - 30*time.Second

// checkStalled 头部比已读位置新、且已读位置隔了一个心跳周期还没动，就是卡住了。
// 只差一次心跳不算：新记录可能刚写进去还没轮到读。
func (c *Collector) checkStalled(head journalPos, now time.Time) bool {
	_, read := c.status.snapshot()
	// 还没有任何已读位置（首次运行、从当前位置开始读）时没有可比的基线。
	behind := head.SeqnumID != "" && read.SeqnumID != "" &&
		(head.SeqnumID != read.SeqnumID || head.Seqnum > read.Seqnum)
	if !behind {
		c.stuckRead = nil
		return false
	}
	if c.stuckRead != nil && *c.stuckRead == read {
		if now.Sub(c.stuckAt) < stallMinGap {
			return false
		}
		c.stuckRead = nil
		return true
	}
	c.stuckRead, c.stuckAt = &read, now
	return false
}

func (c *Collector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	hbTicker := time.NewTicker(HeartbeatInterval)
	defer hbTicker.Stop()
	lastRejectedLog := time.Now()
	// 第一次心跳带上 start，服务端据此知道插件重启过。
	first := true
	beat := func(reasons []string, now time.Time) {
		if first {
			reasons, first = append([]string{HeartbeatStart}, reasons...), false
		}
		c.sendHeartbeat(ctx, reasons, now)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.notifyCh:
			beat(c.pending.take(), time.Now())
		case now := <-hbTicker.C:
			beat(append([]string{HeartbeatPeriodic}, c.pending.take()...), now)
		case now := <-ticker.C:
			for _, out := range c.co.Flush(now) {
				c.send(out)
			}
			if now.Sub(lastRejectedLog) >= rejectedLogInterval {
				c.logRejected()
				lastRejectedLog = now
			}
		}
	}
}

// logRejected 把被拒绝的写入方打进日志。某个发行版的 sshd 不在可信路径名单里时，
// 这里是唯一能看出来的地方——否则表现只是「这台机器没有登录事件」。
func (c *Collector) logRejected() {
	c.mu.Lock()
	snap := c.rejected
	c.rejected = make(map[string]int)
	c.mu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.logger.Warn("认证日志记录的写入方未通过校验，已忽略", zap.String("writer", k), zap.Int("count", snap[k]))
	}
}
