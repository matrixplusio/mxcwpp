package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// journald 给每条记录附带写入进程的程序路径与用户身份（以下划线开头的字段），这些由
// journald 从内核取得，写日志的进程自己改不了。日志文件没有这层保证：本机任何用户都能
// 用 logger -t sshd 写出一行「sshd 说登录成功」。所以优先读 journald，并校验这两项。

// trustedWriters 各进程名对应的可信程序路径。
// 普通用户写不了这些目录，自己编一个同名程序冒充不了。
var trustedWriters = map[string][]string{
	"sshd": {"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"},
	// OpenSSH 9.8 起把会话与认证拆成了独立的程序。
	"sshd-session": {"/usr/libexec/openssh/sshd-session", "/usr/lib/openssh/sshd-session", "/usr/libexec/sshd-session"},
	"sshd-auth":    {"/usr/libexec/openssh/sshd-auth", "/usr/lib/openssh/sshd-auth", "/usr/libexec/sshd-auth"},
	"sudo":         {"/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"},
	"su":           {"/usr/bin/su", "/bin/su"},
	"login":        {"/usr/bin/login", "/bin/login"},
	"useradd":      {"/usr/sbin/useradd", "/sbin/useradd"},
	"userdel":      {"/usr/sbin/userdel", "/sbin/userdel"},
	"usermod":      {"/usr/sbin/usermod", "/sbin/usermod"},
	"groupadd":     {"/usr/sbin/groupadd", "/sbin/groupadd"},
	"gpasswd":      {"/usr/bin/gpasswd", "/bin/gpasswd"},
	"passwd":       {"/usr/bin/passwd", "/bin/passwd"},
}

// rootOnlyWriters 这些进程只有以 root 身份运行时写的才算数。
// 普通用户可以自己起一个 /usr/sbin/sshd 监听高端口，让它写出任意「登录成功」。
var rootOnlyWriters = map[string]bool{"sshd": true, "sshd-session": true, "sshd-auth": true, "login": true}

// journalCandidates journalctl 的可能位置。写死路径而不查 PATH：插件以 root 运行，
// PATH 被改动时不该去执行别处的同名程序。
var journalCandidates = []string{"/usr/bin/journalctl", "/bin/journalctl"}

// ErrJournalUnavailable 本机没有可用的 journalctl，调用方应改读日志文件。
var ErrJournalUnavailable = errors.New("journalctl 不可用")

func findJournalctl() (string, error) {
	for _, p := range journalCandidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", ErrJournalUnavailable
}

// journalArgs 组装 journalctl 的参数。全部是固定值、journal 给出的游标与当前时间，没有外部输入。
//
// 没有游标时按时间定位，只从现在开始、不回放历史（历史日志可能有几个月）。不用 --lines=0：
// 它先跳到「过滤结果」的末尾，过滤结果为空（开机后还没人登录过）时，之后到来的第一批匹配记录会被丢掉——
// 新装主机的首次登录会因此漏报。正常首次运行走的是 firstRunCursor 取到的游标，
// 这里只是取不到游标时的退路。
func journalArgs(cursor string, now time.Time) []string {
	args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(now.Unix(), 10))
	}
	return append(args, journalMatches()...)
}

// journalMatches 只订阅可信名单里的进程名。同一字段的多个匹配是「或」的关系。
func journalMatches() []string {
	names := make([]string, 0, len(trustedWriters))
	for name := range trustedWriters {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, "_COMM="+name)
	}
	return out
}

type journalRecord struct {
	Cursor    string          `json:"__CURSOR"`
	Realtime  string          `json:"__REALTIME_TIMESTAMP"`
	Comm      string          `json:"_COMM"`
	Exe       string          `json:"_EXE"`
	UID       string          `json:"_UID"`
	PID       string          `json:"_PID"`
	MessageRW json.RawMessage `json:"MESSAGE"`
}

// decodeJournalLine 解析 journalctl 的一行 JSON 输出。
// 写入进程不在可信名单里、或身份不符时 ok 为 false——游标照常返回，以便越过这条。
func decodeJournalLine(line []byte) (en Entry, cursor string, ok bool) {
	var rec journalRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return Entry{}, "", false
	}
	cursor = rec.Cursor
	paths, known := trustedWriters[rec.Comm]
	if !known || !containsString(paths, rec.Exe) {
		return Entry{}, cursor, false
	}
	if rootOnlyWriters[rec.Comm] && rec.UID != "0" {
		return Entry{}, cursor, false
	}
	// MESSAGE 通常是字符串；含非 UTF-8 字节时 journalctl 输出成数字数组，这种不解析。
	var msg string
	if err := json.Unmarshal(rec.MessageRW, &msg); err != nil {
		return Entry{}, cursor, false
	}
	en = Entry{Ident: rec.Comm, Message: msg, Trust: TrustJournal, Time: time.Now()}
	if usec, err := strconv.ParseInt(rec.Realtime, 10, 64); err == nil && usec > 0 {
		en.Time = time.UnixMicro(usec)
	}
	en.PID, _ = strconv.Atoi(rec.PID)
	return en, cursor, true
}

// journalHeadTimeout 探测日志头部的 journalctl 最多跑这么久；它只读最后一条，正常是毫秒级。
const journalHeadTimeout = 15 * time.Second

// journalHead 取同一组进程名过滤下 journald 里最新一条记录的位置。
//
// 拿它和已读位置比：头部在前进、已读位置不动，说明 journalctl 被冻住或卡死了——
// 那时心跳照发、位置照报，只看位置和「没人登录」一模一样。
// filtered 为 false 时不按进程名过滤，取整个 journal 的最新一条。
func journalHead(ctx context.Context, filtered bool) (journalPos, error) {
	cursor, err := journalLastCursor(ctx, filtered)
	if err != nil || cursor == "" {
		return journalPos{}, err
	}
	p, ok := parseJournalCursor(cursor)
	if !ok {
		return journalPos{}, errors.New("journal 头部记录没有可用的游标")
	}
	return p, nil
}

// firstRunCursor 首次运行的起点，只从现在开始、不回放历史。
//
// 优先取过滤结果的最后一条：它是一条匹配记录，--after-cursor 从它之后读与续读完全是同一条路。
// 过滤结果为空（开机后还没人登录过）时取整个 journal 的末尾：此时它之后没有任何匹配记录，
// journalctl 会从下一条新记录开始。这个末尾游标指向的是不匹配的记录，不写盘——
// 较老的 journalctl 对「不匹配的游标 + 过滤条件」会把游标之后第一条匹配记录跳过，
// 拿它续读就会丢一条。代价：读到第一条记录之前插件就重启的话，停机期间的匹配记录不会补读；
// 两次查询与启动跟随之间（毫秒级）恰好写进的匹配记录，最多会丢一条。
// 两者都取不到时返回空串，journalArgs 退回按当前时间开始。
func firstRunCursor(ctx context.Context) string {
	if c, err := journalLastCursor(ctx, true); err == nil && c != "" {
		return c
	}
	if c, err := journalTailCursor(ctx); err == nil {
		return c
	}
	return ""
}

// journalTailCursor 整个 journal（不按进程名过滤）最新一条记录的游标。
func journalTailCursor(ctx context.Context) (string, error) {
	c, err := journalLastCursor(ctx, false)
	if err == nil && c == "" {
		err = errors.New("journal 是空的")
	}
	return c, err
}

// journalLastCursor 取最新一条（filtered 时只看可信名单里的进程名）记录的游标；一条都没有时返回空串。
func journalLastCursor(ctx context.Context, filtered bool) (string, error) {
	bin, err := findJournalctl()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, journalHeadTimeout)
	defer cancel()
	args := []string{"--lines=1", "--output=json", "--no-pager", "--quiet"}
	if filtered {
		args = append(args, journalMatches()...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	setChildAttrs(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = lowerChildPriority(cmd.Process.Pid)
	line, _, rerr := readJournalLine(bufio.NewReaderSize(stdout, 64*1024), journalMaxLine)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if errors.Is(rerr, io.EOF) && len(line) == 0 {
		// 一条匹配的记录都没有（新装的机器没人登录过）：不是失败。
		return "", nil
	}
	if rerr != nil {
		return "", rerr
	}
	var rec journalRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return "", err
	}
	// 这个游标会作为 --after-cursor 的参数，与状态文件里的游标同样只接受游标该有的字符。
	if validCursor(rec.Cursor) == "" {
		return "", errors.New("journal 记录的游标格式不对")
	}
	return rec.Cursor, nil
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

const (
	journalCursorFile     = "journal.cursor"
	journalCursorInterval = 5 * time.Second
	journalMaxLine        = 1 << 20
	// journalBadCursorWindow journalctl 启动后这么快就报错退出，才认为是游标本身有问题。
	journalBadCursorWindow = 3 * time.Second
)

// runJournal 跟随 journald 直到 ctx 结束或 journalctl 退出。每条可信记录交给 emit；
// 进程名对得上但程序路径或身份不符的交给 rejected（可为 nil）。
// status 记录读取位置供心跳上报；游标被丢弃时调用 notify（两者都可为 nil）。
func runJournal(ctx context.Context, stateDir string, emit func(Entry), rejected func(comm, exe, uid string),
	status *sourceStatus, notify func(reason string)) error {
	bin, err := findJournalctl()
	if err != nil {
		return err
	}
	cursorPath := filepath.Join(stateDir, journalCursorFile)
	cursor := readCursor(cursorPath)
	if status != nil {
		status.setCursorPath(cursorPath)
	}
	// fromFile 游标来自上次写盘的位置。只有这种才可能「作废」：本轮刚向 journal 查到的起点，
	// journalctl 一启动就退出（比如 inotify 用尽）不代表日志被清，不能删、不能报游标作废。
	fromFile := cursor != ""
	start := cursor
	if !fromFile {
		// 只作为本轮起点；cursor 仍为空，读到第一条记录之前不会写盘。
		start = firstRunCursor(ctx)
	}

	cmd := exec.CommandContext(ctx, bin, journalArgs(start, time.Now())...)
	setChildAttrs(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 journalctl 失败: %w", err)
	}
	started := time.Now()
	// 尽力而为：降不下来（容器里没有 CAP_SYS_NICE 之类）也照常采集。
	_ = lowerChildPriority(cmd.Process.Pid)
	if status != nil {
		if status.setSource(SourceJournal) && notify != nil {
			notify(HeartbeatSourceChanged)
		}
		proc := cmd.Process
		status.setStopper(func() { _ = proc.Kill() })
		defer status.setStopper(nil)
	}

	rd := bufio.NewReaderSize(stdout, 64*1024)
	lastSave := time.Now()
	for {
		line, tooLong, rerr := readJournalLine(rd, journalMaxLine)
		if rerr != nil {
			break
		}
		if tooLong {
			// 跳过这一条继续读。不能就此停下：journalctl 还在往管道里写，没人读它就永远卡住，
			// 而游标还停在这条之前，重启之后又会卡在同一个地方。
			if rejected != nil {
				rejected(oversizedLineMarker, "", "")
			}
			continue
		}
		en, cur, ok := decodeJournalLine(line)
		if status != nil {
			status.noteJournalCursor(cur)
			if !ok {
				status.noteRejected()
			}
		}
		if ok {
			emit(en)
		} else if rejected != nil {
			var rec journalRecord
			if json.Unmarshal(line, &rec) == nil && rec.Comm != "" {
				rejected(rec.Comm, rec.Exe, rec.UID)
			}
		}
		if cur != "" {
			cursor = cur
			if time.Since(lastSave) >= journalCursorInterval {
				saveJournalCursor(cursorPath, cursor, status)
				lastSave = time.Now()
			}
		}
	}
	saveJournalCursor(cursorPath, cursor, status)
	// 读取已经结束（管道关了或出错），journalctl 可能还活着：先结束它，否则 Wait 会一直等。
	_ = cmd.Process.Kill()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		// 保存的游标所在的日志已被轮转清掉时 journalctl 会直接报错退出；
		// 丢掉游标，下次从当前位置重新开始，而不是永远起不来。
		// 只在「一启动就退出」时这么做：跑了一阵子才退出的（被杀、journald 重启）游标是好的，
		// 留着它，重启后能把中间这段补回来；删掉的话退避期间的事件就永久跳过了。
		if time.Since(started) < journalBadCursorWindow && fromFile {
			_ = os.Remove(cursorPath)
			// 游标作废意味着上次读到的位置之后有一段不会再读，要让服务端知道。
			// 注意它不是「日志被清」的可靠信号：游标指向的记录被删掉时 journalctl 通常会跳到最近的位置
			// 照常读下去，不报错；那种情况靠服务端比对序号组与序号发现。这里能触发的多是游标损坏，
			// 或 journalctl 一启动就被杀——后者会让中间一段被跳过，所以照样上报。
			if notify != nil {
				notify(HeartbeatCursorReset)
			}
		}
		return fmt.Errorf("journalctl 退出: %w", waitErr)
	}
	return errors.New("journalctl 意外结束")
}

// oversizedLineMarker 超长行在「被拒绝的写入方」统计里用的名字。
const oversizedLineMarker = "(超过长度上限的行)"

// readJournalLine 读一行，不含换行符。超过 max 的行整行丢弃并返回 tooLong，读取位置落在下一行开头。
// 返回的切片在下一次调用前有效。
func readJournalLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		frag, e := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(frag) > max {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, frag...)
			}
		}
		if e == nil {
			return bytes.TrimRight(buf, "\n"), tooLong, nil
		}
		if !errors.Is(e, bufio.ErrBufferFull) {
			return nil, tooLong, e
		}
	}
}

func readCursor(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return validCursor(strings.TrimSpace(string(b)))
}

// validCursor 游标会作为命令行参数传给 journalctl。状态文件是本机 root 才能写的，这里仍然只接受
// 游标该有的字符，不让一个被改坏的游标变成额外的命令行选项。不合格时返回空串。
func validCursor(c string) string {
	if c == "" || len(c) > 512 || strings.HasPrefix(c, "-") {
		return ""
	}
	for _, r := range c {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '=' || r == ';' || r == '_' || r == '-') {
			return ""
		}
	}
	return c
}

// saveJournalCursor 有状态时经它写盘（与心跳前的刷盘串行、并记下写盘结果），没有时直接写。
func saveJournalCursor(path, cursor string, status *sourceStatus) {
	if status != nil {
		status.saveCursor(cursor)
		return
	}
	writeCursor(path, cursor)
}

func writeCursor(path, cursor string) bool {
	if cursor == "" {
		return false
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(cursor), 0600); err != nil {
		return false
	}
	return os.Rename(tmp, path) == nil
}
