package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestParseJournalCursor(t *testing.T) {
	p, ok := parseJournalCursor("s=6f1c0a;i=1a2b;b=9d3e;m=12;t=5f;x=ab")
	if !ok || p.SeqnumID != "6f1c0a" || p.Seqnum != 0x1a2b || p.BootID != "9d3e" {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
	for _, bad := range []string{"", "s=abc", "i=12", "s=abc;i=zz"} {
		if _, ok := parseJournalCursor(bad); ok {
			t.Errorf("%q 不该解析成功", bad)
		}
	}
}

func TestHeartbeatCarriesPositionAndResetsCounters(t *testing.T) {
	s := newSourceStatus()
	if !s.setSource(SourceJournal) || s.setSource(SourceJournal) {
		t.Fatal("setSource 只在来源真的变了时返回 true")
	}
	s.noteJournalCursor("s=aa;i=10;b=bb")
	s.noteJournalCursor("s=aa;i=11;b=bb")
	s.noteRejected()
	// 读到但还没写盘的位置不上报：插件此刻被停掉，重启后会从更早的游标续读。
	if f := s.heartbeat(nil, heartbeatProbe{}, time.Unix(50, 0)).Fields(); f["journal_seqnum"] != "" {
		t.Fatalf("未写盘的位置不该上报，得 %q", f["journal_seqnum"])
	}
	s.noteJournalCursor("s=aa;i=10;b=bb")
	s.noteJournalCursor("s=aa;i=11;b=bb")
	s.noteRejected()
	s.setCursorPath(filepath.Join(t.TempDir(), journalCursorFile))
	s.saveCursor("s=aa;i=11;b=bb")
	s.noteJournalCursor("s=aa;i=12;b=bb") // 写盘之后又读了一条，仍报写盘的 0x11

	f := s.heartbeat([]string{HeartbeatPeriodic}, heartbeatProbe{}, time.Unix(100, 0)).Fields()
	want := map[string]string{
		"event_type": KindHeartbeat, "reason": HeartbeatPeriodic, "source": SourceJournal,
		"journal_seqnum_id": "aa", "journal_seqnum": "17", "journal_boot_id": "bb",
		"read": "3", "rejected": "1", "trust": TrustJournal,
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %q, want %q", k, f[k], v)
		}
	}
	if _, ok := f["journal_persistent"]; !ok {
		t.Error("journald 来源的心跳要带 journal_persistent")
	}
	f2 := s.heartbeat([]string{HeartbeatPeriodic}, heartbeatProbe{}, time.Unix(400, 0)).Fields()
	if f2["read"] != "0" || f2["rejected"] != "0" {
		t.Errorf("计数应在每次心跳后清零: %v", f2)
	}
	if f["instance_id"] == "" || f["instance_id"] != f2["instance_id"] || f["hb_seq"] != "2" || f2["hb_seq"] != "3" {
		t.Errorf("同一进程的心跳应带同一个实例号与递增的序号: %v / %v", f, f2)
	}
}

func TestEventExtraCannotOverrideCoreFields(t *testing.T) {
	ev := &Event{Kind: KindHeartbeat, Time: time.Unix(1, 0), Count: 1,
		Extra: map[string]string{"event_type": "auth_login_success", "source": "file"}}
	f := ev.Fields()
	if f["event_type"] != KindHeartbeat || f["source"] != "file" {
		t.Fatalf("got %v", f)
	}
}

func TestReadNewLinesReportsInPlaceTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st := fileState{Path: path, Offset: -1}
	st, _ = readNewLines(st, func(Entry) {})

	// 原地截断：inode 不变、文件变短。
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	st, res := readNewLines(st, func(Entry) {})
	if !res.truncated || st.Offset != 0 {
		t.Fatalf("原地截断应当报出来: res=%+v st=%+v", res, st)
	}

	// 轮转：换成新文件，不算截断。
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, res = readNewLines(st, func(Entry) {})
	if res.truncated || res.lines != 1 {
		t.Fatalf("轮转不是截断: %+v", res)
	}
}

func TestSeedJournalGivesBaselineAfterRestart(t *testing.T) {
	s := newSourceStatus()
	s.setSource(SourceJournal)
	s.seedJournal("s=aa;i=ff;b=bb")
	f := s.heartbeat([]string{HeartbeatStart}, heartbeatProbe{}, time.Unix(1, 0)).Fields()
	if f["journal_seqnum_id"] != "aa" || f["journal_seqnum"] != "255" || f["read"] != "0" {
		t.Fatalf("重启后的第一条心跳应带上次保存的位置: %v", f)
	}
}

func TestCheckStalledNeedsTwoBeatsBehind(t *testing.T) {
	c := NewCollector(zap.NewNop(), t.TempDir(), func(*Event) {})
	c.status.setSource(SourceJournal)
	c.status.noteJournalCursor("s=aa;i=10;b=bb")
	head := journalPos{SeqnumID: "aa", Seqnum: 0x20}
	t0 := time.Unix(1000, 0)
	beat := func(i int) time.Time { return t0.Add(time.Duration(i) * HeartbeatInterval) }
	if c.checkStalled(head, beat(0)) {
		t.Fatal("落后一次不算卡住")
	}
	if c.checkStalled(head, beat(0).Add(time.Second)) {
		t.Fatal("即时心跳紧跟着来，读取位置来不及动，不算卡住")
	}
	if !c.checkStalled(head, beat(1)) {
		t.Fatal("隔了一个心跳周期仍落后且已读位置没动，应判卡住")
	}
	// 追上了就清零。
	c.status.noteJournalCursor("s=aa;i=20;b=bb")
	if c.checkStalled(head, beat(2)) || c.checkStalled(head, beat(3)) {
		t.Fatal("已读追上头部后不算卡住")
	}
	// 读取在前进（只是还没追上）也不算。
	c.status.noteJournalCursor("s=aa;i=12;b=bb")
	c.checkStalled(head, beat(4))
	c.status.noteJournalCursor("s=aa;i=14;b=bb")
	if c.checkStalled(head, beat(5)) {
		t.Fatal("已读位置在动就不是卡住")
	}
	// 没有已读基线时不判。
	c2 := NewCollector(zap.NewNop(), t.TempDir(), func(*Event) {})
	if c2.checkStalled(head, beat(0)) || c2.checkStalled(head, beat(1)) {
		t.Fatal("没有已读位置时不判")
	}
}

func TestProcessRunning(t *testing.T) {
	root := t.TempDir()
	for pid, pc := range map[string][2]string{
		"1":    {"systemd", "/usr/lib/systemd/systemd"},
		"321":  {"systemd-journal", "/usr/lib/systemd/systemd-journald (deleted)"},
		"400":  {"rsyslogd", "/usr/bin/sleep"},
		"self": {"x", "/x"},
	} {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "comm"), []byte(pc[0]+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Symlink(pc[1], filepath.Join(root, pid, "exe"))
	}
	if !processRunning(root, journaldComms) {
		t.Error("journald 在跑（程序升级后链接带 (deleted) 也算）")
	}
	if processRunning(root, syslogComms) {
		t.Error("软链成 rsyslogd 的 sleep 不算日志服务")
	}
	if !processRunning(filepath.Join(root, "nope"), syslogComms) {
		t.Error("读不了 /proc 时不能报日志服务停了")
	}
}

func TestNotifyKeepsEveryReason(t *testing.T) {
	c := NewCollector(zap.NewNop(), t.TempDir(), func(*Event) {})
	c.notify(HeartbeatFileTruncated)
	c.notify(HeartbeatCursorReset)
	c.notify(HeartbeatFileTruncated)
	got := c.pending.take()
	if len(got) != 2 || got[0] != HeartbeatCursorReset || got[1] != HeartbeatFileTruncated {
		t.Fatalf("got %v", got)
	}
	if len(c.pending.take()) != 0 {
		t.Fatal("取走后应清空")
	}
}

func TestReadNewLinesReportsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure")
	if err := os.WriteFile(path, []byte("a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st, _ := readNewLines(fileState{Path: path, Offset: -1}, func(Entry) {})
	if err := os.Rename(path, path+"-x"); err != nil {
		t.Fatal(err)
	}
	if _, res := readNewLines(st, func(Entry) {}); !res.missing {
		t.Fatal("文件被改名走后应报不存在")
	}
	s := newSourceStatus()
	s.setSource(SourceFile)
	s.noteFile(st, 0, true)
	if f := s.heartbeat(nil, heartbeatProbe{}, time.Unix(1, 0)).Fields(); f["file_missing"] != "true" {
		t.Fatalf("心跳应带 file_missing: %v", f)
	}
}

func TestWriterMismatch(t *testing.T) {
	newRoot := func() (root, logFile, renamed string, ino uint64) {
		root = t.TempDir()
		logFile = filepath.Join(root, "secure")
		renamed = filepath.Join(root, "secure-20261022")
		for _, f := range []string{logFile, renamed} {
			if err := os.WriteFile(f, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		fi, _ := os.Stat(logFile)
		return root, logFile, renamed, inodeOf(fi)
	}
	mk := func(root, pid, comm, exe string, targets ...string) {
		if err := os.MkdirAll(filepath.Join(root, pid, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.Symlink(exe, filepath.Join(root, pid, "exe"))
		for i, tg := range targets {
			_ = os.Symlink(tg, filepath.Join(root, pid, "fd", fmt.Sprint(3+i)))
		}
	}

	root, logFile, _, ino := newRoot()
	mk(root, "100", "rsyslogd", "/usr/sbin/rsyslogd", logFile, filepath.Join(root, "messages"))
	if writerMismatch(root, syslogComms, logFile, ino) {
		t.Fatal("日志服务写的就是这个文件")
	}
	// 轮转后 HUP，rsyslog 关了所有文件、还没等到下一条认证日志：手里没有这个文件不算异常。
	root, logFile, _, ino = newRoot()
	mk(root, "100", "rsyslogd", "/usr/sbin/rsyslogd", filepath.Join(root, "messages"))
	if writerMismatch(root, syslogComms, logFile, ino) {
		t.Fatal("rsyslog 暂时没打开认证日志不算不一致")
	}

	// 改名后换上空文件：rsyslog 还写着改了名的旧文件。冒充的进程、或另起的真 rsyslogd 打开新文件都不能放行。
	root, logFile, renamed, ino := newRoot()
	mk(root, "100", "rsyslogd", "/usr/sbin/rsyslogd", renamed)
	mk(root, "150", "rsyslogd", "/usr/bin/sleep", logFile)
	if !writerMismatch(root, syslogComms, logFile, ino) {
		t.Fatal("rsyslog 写的是改了名的旧文件")
	}
	mk(root, "200", "rsyslogd", "/usr/sbin/rsyslogd", logFile)
	if !writerMismatch(root, syslogComms, logFile, ino) {
		t.Fatal("另起一个 rsyslogd 打开新文件，原来那个仍写旧文件，应报")
	}
	if writerMismatch(filepath.Join(root, "nope"), syslogComms, logFile, ino) {
		t.Fatal("判断不了时不报")
	}
}

// 心跳前把读到但没写盘的游标刷下去：安静的主机上最后几条一直不写盘的话，上报位置停在更早处，
// 那几条被替换后服务端比不出倒退。
func TestFlushCursorBeforeHeartbeat(t *testing.T) {
	s := newSourceStatus()
	s.setSource(SourceJournal)
	path := filepath.Join(t.TempDir(), journalCursorFile)
	s.setCursorPath(path)
	s.noteJournalCursor("s=aa;i=10;b=bb")
	s.saveCursor("s=aa;i=10;b=bb")
	s.noteJournalCursor("s=aa;i=15;b=bb")

	s.flushCursor()
	f := s.heartbeat(nil, heartbeatProbe{}, time.Unix(1, 0)).Fields()
	if f["journal_seqnum"] != "21" {
		t.Fatalf("刷盘后应上报 0x15=21，得 %q", f["journal_seqnum"])
	}
	if got := readCursor(path); got != "s=aa;i=15;b=bb" {
		t.Fatalf("游标文件 = %q", got)
	}
}

// 写盘失败要在心跳里看得到，且上报位置不前进。
func TestCursorSaveFailureIsReported(t *testing.T) {
	s := newSourceStatus()
	s.setSource(SourceJournal)
	s.setCursorPath(filepath.Join(t.TempDir(), "no-such-dir", journalCursorFile))
	s.noteJournalCursor("s=aa;i=10;b=bb")
	s.flushCursor()
	f := s.heartbeat(nil, heartbeatProbe{}, time.Unix(1, 0)).Fields()
	if f["cursor_save_failed"] != "true" || f["journal_seqnum"] != "" {
		t.Fatalf("写盘失败应上报且不带位置: %v", f)
	}
	if f2 := s.heartbeat(nil, heartbeatProbe{}, time.Unix(2, 0)).Fields(); f2["cursor_save_failed"] != "" {
		t.Fatalf("失败标记应在上报后清掉: %v", f2)
	}
}

// 较旧的游标后到时不能把已写盘的位置往回改。
func TestSaveCursorNeverGoesBackward(t *testing.T) {
	s := newSourceStatus()
	path := filepath.Join(t.TempDir(), journalCursorFile)
	s.setCursorPath(path)
	s.saveCursor("s=aa;i=20;b=bb")
	s.saveCursor("s=aa;i=10;b=bb")
	if got := readCursor(path); got != "s=aa;i=20;b=bb" {
		t.Fatalf("游标被往回写成 %q", got)
	}
	// 序号组换了（journal 被重建）要能写下去。
	s.saveCursor("s=cc;i=1;b=bb")
	if got := readCursor(path); got != "s=cc;i=1;b=bb" {
		t.Fatalf("换组后应写入新游标，得 %q", got)
	}
}
