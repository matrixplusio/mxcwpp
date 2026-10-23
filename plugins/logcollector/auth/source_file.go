package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// 日志文件来源，只在本机没有 journalctl 时使用。
// 这条路没有「写入进程是谁」的保证，事件一律标成 TrustFile。

// authLogFiles 各发行版的认证日志位置，取第一个存在的。
var authLogFiles = []string{"/var/log/secure", "/var/log/auth.log"}

// ErrNoLogSource 既没有 journalctl 也没有认证日志文件。
var ErrNoLogSource = errors.New("没有可读的认证日志来源")

var (
	// Oct 13 01:02:03 host sshd[1234]: message
	reSyslogBSD = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ ([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: (.*)$`)
	// 2026-10-13T01:02:03.123456+08:00 host sshd[1234]: message
	reSyslogISO = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+) \S+ ([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: (.*)$`)
)

var monthIndex = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

// parseSyslogLine 解析一行 syslog 格式的日志。
func parseSyslogLine(line string, now time.Time) (Entry, bool) {
	if m := reSyslogISO.FindStringSubmatch(line); m != nil {
		ts, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			ts = now
		}
		pid, _ := strconv.Atoi(m[3])
		return Entry{Time: ts, Ident: filepath.Base(m[2]), PID: pid, Message: m[4], Trust: TrustFile}, true
	}
	m := reSyslogBSD.FindStringSubmatch(line)
	if m == nil {
		return Entry{}, false
	}
	day, _ := strconv.Atoi(m[2])
	hh, _ := strconv.Atoi(m[3])
	mm, _ := strconv.Atoi(m[4])
	ss, _ := strconv.Atoi(m[5])
	// 这种格式不带年份。按今年算；算出来在未来（跨年时读到去年 12 月的行）就退一年。
	ts := time.Date(now.Year(), monthIndex[m[1]], day, hh, mm, ss, 0, now.Location())
	if ts.After(now.Add(24 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}
	pid, _ := strconv.Atoi(m[7])
	return Entry{Time: ts, Ident: filepath.Base(m[6]), PID: pid, Message: m[8], Trust: TrustFile}, true
}

type fileState struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

const (
	fileStateName    = "file.state"
	filePollInterval = 2 * time.Second
	fileMaxLine      = 64 * 1024
)

func findAuthLogFile() (string, error) {
	for _, p := range authLogFiles {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", ErrNoLogSource
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// runFile 轮询认证日志文件直到 ctx 结束。处理日志轮转（文件被换掉或截断）。
// status 记录读取位置供心跳上报；文件被原地截断时调用 notify（两者都可为 nil）。
func runFile(ctx context.Context, stateDir string, emit func(Entry), status *sourceStatus, notify func(reason string)) error {
	path, err := findAuthLogFile()
	if err != nil {
		return err
	}
	statePath := filepath.Join(stateDir, fileStateName)
	var st fileState
	if b, e := os.ReadFile(statePath); e == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Path != path {
		st = fileState{Path: path, Offset: -1} // -1：首次运行，从文件末尾开始，不回放历史
	}

	if status != nil && status.setSource(SourceFile) && notify != nil {
		notify(HeartbeatSourceChanged)
	}
	ticker := time.NewTicker(filePollInterval)
	defer ticker.Stop()
	saved := fileState{}
	for {
		var res readResult
		st, res = readNewLines(st, emit)
		if status != nil {
			status.noteFile(st, res.lines, res.missing)
		}
		if res.truncated && notify != nil {
			notify(HeartbeatFileTruncated)
		}
		// 位置没变就不写：多数时候没有新日志，每两秒写一次盘纯属浪费。
		if st != saved {
			if b, e := json.Marshal(st); e == nil && os.WriteFile(statePath, b, 0600) == nil {
				saved = st
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// readResult 一次读取的附带结果。
type readResult struct {
	lines uint64
	// missing 认证日志文件不存在（打开时 ENOENT）。
	missing bool
	// truncated 同一个文件变短了。轮转是换成新文件（inode 变了），原地变短的只有截断：
	// 用 copytruncate 轮转的 logrotate 会这样做，清痕迹的人也会这样做，服务端结合上下文判断。
	truncated bool
}

// readNewLines 读出上次位置之后的完整行，返回新的位置。
func readNewLines(st fileState, emit func(Entry)) (fileState, readResult) {
	var res readResult
	f, err := os.Open(st.Path)
	if err != nil {
		res.missing = errors.Is(err, fs.ErrNotExist)
		return st, res
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return st, res
	}
	ino := inodeOf(fi)
	switch {
	case st.Offset < 0:
		st.Inode, st.Offset = ino, fi.Size()
		return st, res
	case ino != st.Inode || fi.Size() < st.Offset:
		// 文件被轮转或截断：新文件从头读。旧文件里没读完的尾巴放弃，
		// 那最多是一个轮询间隔的内容。
		res.truncated = ino == st.Inode
		st.Inode, st.Offset = ino, 0
	}
	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return st, res
	}
	r := bufio.NewReaderSize(f, fileMaxLine)
	now := time.Now()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			// 没有换行符的半行留到下次，位置不前移。
			return st, res
		}
		st.Offset += int64(len(line))
		res.lines++
		if len(line) > fileMaxLine {
			continue
		}
		if en, ok := parseSyslogLine(line[:len(line)-1], now); ok {
			emit(en)
		}
	}
}
