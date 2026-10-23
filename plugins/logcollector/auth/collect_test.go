package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func failedFrom(ip, user string, at time.Time) *Event {
	return &Event{Kind: KindLoginFailed, Service: "sshd", Username: user, SourceIP: ip, Reason: "password", Time: at, Count: 1}
}

// 同一来源同一账号：第一条立即放行，窗口内其余的合并成一条汇总，次数不丢。
func TestCoalescerMergesRepeatedFailures(t *testing.T) {
	c := newCoalescer()
	t0 := time.Unix(1760000000, 0)

	if out := c.Offer(failedFrom("203.0.113.9", "root", t0), t0); len(out) != 1 || out[0].Count != 1 {
		t.Fatalf("第一条应立即上报：%v", out)
	}
	for i := 1; i <= 50; i++ {
		at := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		if out := c.Offer(failedFrom("203.0.113.9", "root", at), at); len(out) != 0 {
			t.Fatalf("窗口内的重复不该逐条上报")
		}
	}
	// 另一个来源、另一个账号各自独立。
	if out := c.Offer(failedFrom("198.51.100.7", "root", t0), t0); len(out) != 1 {
		t.Fatal("不同来源应独立上报")
	}
	if out := c.Offer(failedFrom("203.0.113.9", "admin", t0), t0); len(out) != 1 {
		t.Fatal("不同账号应独立上报")
	}

	if out := c.Flush(t0.Add(coalesceWindow - time.Second)); len(out) != 0 {
		t.Fatalf("窗口未结束不该汇总：%v", out)
	}
	out := c.Flush(t0.Add(coalesceWindow + time.Second))
	if len(out) != 1 || out[0].Count != 50 || out[0].SourceIP != "203.0.113.9" || out[0].Username != "root" {
		t.Fatalf("汇总应为 1 条、次数 50：%+v", out)
	}
	// 窗口结束后同一来源再来，重新立即上报。
	t1 := t0.Add(coalesceWindow + 2*time.Second)
	if out := c.Offer(failedFrom("203.0.113.9", "root", t1), t1); len(out) != 1 {
		t.Fatal("新窗口的第一条应立即上报")
	}
}

// 成功登录、sudo 执行这类事件不合并：每一条都是独立的事实。
func TestCoalescerPassesNonRepetitiveKinds(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	for i := 0; i < 5; i++ {
		ev := &Event{Kind: KindLoginSuccess, Username: "alice", SourceIP: "10.0.0.5", Count: 1}
		if out := c.Offer(ev, now); len(out) != 1 {
			t.Fatal("成功登录不该被合并")
		}
	}
}

// 超过每分钟限额的丢弃并计数，丢弃数随后上报——不能悄悄少数据。
func TestCoalescerRateLimitReportsDrops(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	sent := 0
	for i := 0; i < rateLimitPerMinute+300; i++ {
		ev := &Event{Kind: KindSudo, Username: "deploy", Command: "/usr/bin/id", Count: 1}
		sent += len(c.Offer(ev, now))
	}
	if sent != rateLimitPerMinute {
		t.Fatalf("放行 %d 条，期望 %d", sent, rateLimitPerMinute)
	}
	if out := c.Flush(now.Add(30 * time.Second)); len(out) != 0 {
		t.Fatalf("这一分钟还没过，统计先不报：%v", out)
	}
	out := c.Flush(now.Add(61 * time.Second))
	if len(out) != 1 || out[0].Kind != KindStats || out[0].Count != 300 || out[0].Reason != "rate_limited" {
		t.Fatalf("应上报 300 条被丢弃：%+v", out)
	}
	// 下一分钟限额恢复。
	if got := c.Offer(&Event{Kind: KindSudo, Count: 1}, now.Add(62*time.Second)); len(got) != 1 {
		t.Fatal("新的一分钟应恢复放行")
	}
}

// 分布式爆破：来源数超过合并表上限时不再开新窗口，表不随来源数无限增长。
func TestCoalescerBoundsTrackedSources(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	for i := 0; i < coalesceMaxKeys+500; i++ {
		ip := "198.51." + itoa(i/250) + "." + itoa(i%250)
		c.Offer(failedFrom(ip, "root", now), now)
	}
	if len(c.opened) > coalesceMaxKeys {
		t.Fatalf("合并表有 %d 项，超过上限 %d", len(c.opened), coalesceMaxKeys)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func journalLine(comm, exe, uid, msg string) []byte {
	return []byte(`{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1760000000123456","_COMM":"` + comm +
		`","_EXE":"` + exe + `","_UID":"` + uid + `","_PID":"4321","MESSAGE":"` + msg + `"}`)
}

// 只认可信路径下、身份正确的进程写的记录。
func TestDecodeJournalLineChecksWriter(t *testing.T) {
	const ok = "Accepted password for root from 10.0.0.1 port 22 ssh2"
	en, cur, good := decodeJournalLine(journalLine("sshd", "/usr/sbin/sshd", "0", ok))
	if !good || en.Ident != "sshd" || en.Message != ok || en.PID != 4321 || en.Trust != TrustJournal || cur != "s=abc;i=1" {
		t.Fatalf("正常记录解析失败：%+v cursor=%q ok=%v", en, cur, good)
	}
	if en.Time.Unix() != 1760000000 {
		t.Errorf("时间应取自日志自身：%v", en.Time)
	}

	rejected := []struct{ name, comm, exe, uid string }{
		{"普通用户自己起的 sshd", "sshd", "/usr/sbin/sshd", "1000"},
		{"用户目录下的同名程序", "sshd", "/home/eve/sshd", "0"},
		{"/tmp 下的同名程序", "sudo", "/tmp/sudo", "0"},
		{"名单之外的进程", "logger", "/usr/bin/logger", "0"},
		{"没有程序路径", "sshd", "", "0"},
	}
	for _, r := range rejected {
		_, cur, good := decodeJournalLine(journalLine(r.comm, r.exe, r.uid, ok))
		if good {
			t.Errorf("%s：不该被接受", r.name)
		}
		if cur == "" {
			t.Errorf("%s：被拒绝的记录也要返回游标，否则读取位置会卡住", r.name)
		}
	}
	// sudo 由普通用户发起，进程身份不是 root 也要接受（程序路径可信即可）。
	if _, _, good := decodeJournalLine(journalLine("sudo", "/usr/bin/sudo", "1000", "x")); !good {
		t.Error("sudo 的记录不该按 root 身份过滤")
	}
	if _, _, good := decodeJournalLine([]byte(`{"_COMM":"sshd","_EXE":"/usr/sbin/sshd","_UID":"0","MESSAGE":[65,66]}`)); good {
		t.Error("非字符串的 MESSAGE 不解析")
	}
	if _, _, good := decodeJournalLine([]byte(`not json`)); good {
		t.Error("非 JSON 行不解析")
	}
}

func TestJournalArgs(t *testing.T) {
	now := time.Unix(1700000000, 0)
	first := strings.Join(journalArgs("", now), " ")
	if !strings.Contains(first, "--since=@1700000000") || strings.Contains(first, "--after-cursor") {
		t.Errorf("没有游标时应按当前时间开始：%s", first)
	}
	resumed := strings.Join(journalArgs("s=abc;i=1", now), " ")
	if !strings.Contains(resumed, "--after-cursor=s=abc;i=1") || strings.Contains(resumed, "--since") {
		t.Errorf("有游标时应从游标之后继续：%s", resumed)
	}
	for _, a := range []string{first, resumed} {
		// --lines=0 在过滤结果为空时会丢掉之后到来的第一批匹配记录，任何情况下都不能再用。
		if strings.Contains(a, "--lines=0") {
			t.Errorf("不应使用 --lines=0：%s", a)
		}
	}
	if !strings.Contains(first, "_COMM=sshd") || !strings.Contains(first, "_COMM=sudo") {
		t.Errorf("应按进程名过滤：%s", first)
	}
}

// fakeJournalctl 写一个假的 journalctl：--lines=1 带过滤条件时输出 filtered、不带时输出 tail（为空则不输出）；
// --follow 时把参数记进 argsFile，以 followExit 退出。
func fakeJournalctl(t *testing.T, filtered, tail string, followExit int) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "follow.args")
	out := func(c string) string {
		if c == "" {
			return ":"
		}
		return fmt.Sprintf(`printf '%%s\n' '{"__CURSOR":"%s","_COMM":"x"}'`, c)
	}
	script := fmt.Sprintf("#!/bin/sh\ncase \"$*\" in\n*--follow*) echo \"$*\" > %s; exit %d ;;\n*_COMM=*) %s ;;\n*) %s ;;\nesac\n",
		argsFile, followExit, out(filtered), out(tail))
	bin := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := journalCandidates
	journalCandidates = []string{bin}
	t.Cleanup(func() { journalCandidates = old })
	return argsFile
}

func runFirstJournal(t *testing.T, state string, notify func(string)) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runJournal(ctx, state, func(Entry) {}, nil, newSourceStatus(), notify)
	return state
}

func TestFirstRunStartPosition(t *testing.T) {
	cases := []struct {
		name, filtered, tail, wantArg string
	}{
		// 有匹配记录：从最后一条匹配记录之后读，与续读同一条路。
		{"有过滤结果", "s=aa;i=40;b=bb", "s=aa;i=64;b=bb", "--after-cursor=s=aa;i=40;b=bb"},
		// 过滤结果为空：从整个 journal 末尾之后读，不写盘（不匹配的游标拿来续读会跳过一条）。
		{"过滤结果为空", "", "s=aa;i=64;b=bb", "--after-cursor=s=aa;i=64;b=bb"},
		// journal 为空：按当前时间开始。
		{"journal 为空", "", "", "--since=@"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			argsFile := fakeJournalctl(t, c.filtered, c.tail, 0)
			state := runFirstJournal(t, t.TempDir(), nil)
			args, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatalf("没有启动跟随用的 journalctl: %v", err)
			}
			if !strings.Contains(string(args), c.wantArg) || strings.Contains(string(args), "--lines=0") {
				t.Fatalf("参数 %s 里应有 %s", args, c.wantArg)
			}
			if _, err := os.Stat(filepath.Join(state, journalCursorFile)); err == nil {
				t.Fatal("首次运行取到的起点不该在读到记录前写盘")
			}
		})
	}
}

// 首次运行时跟随一启动就失败（比如 inotify 用尽）：本轮刚查到的起点不算游标作废，不能反复报。
func TestFirstRunFastFailureIsNotCursorReset(t *testing.T) {
	fakeJournalctl(t, "s=aa;i=40;b=bb", "s=aa;i=64;b=bb", 1)
	var reasons []string
	runFirstJournal(t, t.TempDir(), func(r string) { reasons = append(reasons, r) })
	for _, r := range reasons {
		if r == HeartbeatCursorReset {
			t.Fatalf("首次运行的快速失败不该上报游标作废: %v", reasons)
		}
	}
}

// 写过盘的游标一启动就失败才算作废：删掉并上报一次。
func TestSavedCursorFastFailureIsReset(t *testing.T) {
	fakeJournalctl(t, "", "", 1)
	state := t.TempDir()
	if !writeCursor(filepath.Join(state, journalCursorFile), "s=aa;i=40;b=bb") {
		t.Fatal("写游标失败")
	}
	var reasons []string
	runFirstJournal(t, state, func(r string) { reasons = append(reasons, r) })
	found := false
	for _, r := range reasons {
		found = found || r == HeartbeatCursorReset
	}
	if !found {
		t.Fatalf("写过盘的游标快速失败应上报游标作废: %v", reasons)
	}
}

// 状态文件里的游标会成为命令行参数，只接受游标该有的样子。
func TestReadCursorRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c")
	write := func(v string) { _ = os.WriteFile(p, []byte(v), 0600) }

	write("s=0123abc;i=1f;b=77;m=9;t=5;x=2\n")
	if got := readCursor(p); got != "s=0123abc;i=1f;b=77;m=9;t=5;x=2" {
		t.Errorf("正常游标应原样读出：%q", got)
	}
	for _, bad := range []string{"--file=/etc/shadow", "s=1 --output=cat", "s=1\n--flush", "", strings.Repeat("a", 600)} {
		write(bad)
		if got := readCursor(p); got != "" {
			t.Errorf("游标 %q 应被拒绝，得 %q", bad, got)
		}
	}
	if got := readCursor(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("文件不存在应返回空：%q", got)
	}
}

func TestParseSyslogLine(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.Local)
	en, ok := parseSyslogLine("Oct 13 01:02:03 web-01 sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2", now)
	if !ok || en.Ident != "sshd" || en.PID != 1234 || en.Trust != TrustFile ||
		en.Message != "Accepted password for root from 10.0.0.1 port 22 ssh2" || en.Time.Hour() != 1 || en.Time.Year() != 2026 {
		t.Fatalf("BSD 格式：%+v ok=%v", en, ok)
	}
	en, ok = parseSyslogLine("2026-10-13T01:02:03.123456+08:00 web-01 sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", now)
	if !ok || en.Ident != "sudo" || en.PID != 0 || !strings.HasPrefix(en.Message, "alice : TTY=") || en.Time.Year() != 2026 {
		t.Fatalf("ISO 格式：%+v ok=%v", en, ok)
	}
	// 跨年：一月读到去年十二月的行。
	jan := time.Date(2027, 1, 1, 0, 5, 0, 0, time.Local)
	if en, _ := parseSyslogLine("Dec 31 23:59:00 h sshd[1]: x", jan); en.Time.Year() != 2026 {
		t.Errorf("跨年的行应算作去年：%v", en.Time)
	}
	if _, ok := parseSyslogLine("garbage without header", now); ok {
		t.Error("没有 syslog 头的行不解析")
	}
}

// 文件来源：首次从末尾开始、只读完整的行、文件被轮转后从头读新文件。
func TestReadNewLinesFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	line := func(user string) string {
		return "Oct 13 01:02:03 h sshd[1]: Accepted password for " + user + " from 10.0.0.1 port 22 ssh2\n"
	}
	if err := os.WriteFile(path, []byte(line("old")), 0600); err != nil {
		t.Fatal(err)
	}
	var got []string
	emit := func(en Entry) {
		if ev := Parse(en); ev != nil {
			got = append(got, ev.Username)
		}
	}
	st := fileState{Path: path, Offset: -1}

	st, _ = readNewLines(st, emit)
	if len(got) != 0 {
		t.Fatalf("首次运行不该回放历史：%v", got)
	}

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString(line("alice") + "Oct 13 01:02:04 h sshd[1]: Accepted password for bo")
	st, _ = readNewLines(st, emit)
	if len(got) != 1 || got[0] != "alice" {
		t.Fatalf("应只读到完整的一行：%v", got)
	}
	_, _ = f.WriteString("b from 10.0.0.1 port 22 ssh2\n")
	_ = f.Close()
	st, _ = readNewLines(st, emit)
	if len(got) != 2 || got[1] != "bob" {
		t.Fatalf("半行补全后应读到：%v", got)
	}

	// 轮转：旧文件改名，新文件从头写。
	_ = os.Rename(path, path+".1")
	if err := os.WriteFile(path, []byte(line("carol")), 0600); err != nil {
		t.Fatal(err)
	}
	st, _ = readNewLines(st, emit)
	if len(got) != 3 || got[2] != "carol" {
		t.Fatalf("轮转后应从头读新文件：%v", got)
	}
	if _, _ = readNewLines(st, emit); len(got) != 3 {
		t.Fatalf("没有新内容时不该重复读：%v", got)
	}
}

// 一类事件的洪泛不能挤掉别的类。
//
// 限额共用一个总数时，循环执行 sudo 就能用完它，同一分钟里的登录成功、新建账号、
// root 口令失败随之全部丢弃。
func TestCoalescerFloodOfOneKindDoesNotStarveOthers(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	for i := 0; i < rateLimitPerMinute*3; i++ {
		c.Offer(&Event{Kind: KindSudo, Username: "x", Command: "/usr/bin/true", Count: 1}, now)
	}
	for _, ev := range []*Event{
		{Kind: KindLoginSuccess, Username: "root", SourceIP: "203.0.113.9", Count: 1},
		{Kind: KindAccountChange, Username: "backdoor", Reason: "user_created_uid0", Count: 1},
		{Kind: KindLoginFailed, Username: "root", SourceIP: "203.0.113.9", Count: 1},
		{Kind: KindSuSuccess, Username: "x", TargetUser: "root", Count: 1},
	} {
		if got := c.Offer(ev, now.Add(time.Second)); len(got) != 1 {
			t.Errorf("sudo 洪泛之后 %s 仍应上报，得 %d 条", ev.Kind, len(got))
		}
	}
	out := c.Flush(now.Add(61 * time.Second))
	var stats *Event
	for _, e := range out {
		if e.Kind == KindStats {
			stats = e
		}
	}
	if stats == nil || stats.Count != rateLimitPerMinute*2 || stats.Detail != KindSudo+"="+strconv.Itoa(rateLimitPerMinute*2) {
		t.Fatalf("丢弃统计应写明是哪一类丢了多少：%+v", stats)
	}
}

// 持续洪泛时丢弃统计也要发得出来。
//
// 限额的分钟每到点就被下一条事件重新起算；统计若跟着它判断「这一分钟过完没有」，
// 在事件不断的情况下永远是「还没」——最需要这条统计的时候恰好收不到。
func TestCoalescerStatsEmittedDuringSustainedFlood(t *testing.T) {
	c := newCoalescer()
	start := time.Unix(1760000000, 0)
	stats, dropped := 0, 0
	// 每秒 50 条，持续 10 分钟，每 2 秒刷一次。
	for sec := 0; sec < 600; sec++ {
		now := start.Add(time.Duration(sec) * time.Second)
		for i := 0; i < 50; i++ {
			c.Offer(&Event{Kind: KindSudo, Username: "x", Count: 1}, now)
		}
		if sec%2 == 1 {
			for _, e := range c.Flush(now) {
				if e.Kind == KindStats {
					stats++
					dropped += e.Count
				}
			}
		}
	}
	if stats < 8 {
		t.Fatalf("10 分钟的持续洪泛应大约每分钟报一次丢弃统计，只报了 %d 次", stats)
	}
	if want := 600*50 - 10*rateLimitPerMinute; dropped < want*8/10 {
		t.Fatalf("报出的丢弃数 %d 远小于实际丢弃的约 %d", dropped, want)
	}
}

// 登录成功之前，同一来源压着没报的失败要先报出去，顺序不能反。
func TestCoalescerFlushesPendingFailuresBeforeSuccess(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	fail := func(ip string) []*Event {
		return c.Offer(&Event{Kind: KindLoginFailed, Username: "root", SourceIP: ip, Reason: "password", Count: 1}, now)
	}
	if got := fail("203.0.113.9"); len(got) != 1 {
		t.Fatalf("第一条失败应立即上报，得 %d 条", len(got))
	}
	for i := 0; i < 4; i++ {
		if got := fail("203.0.113.9"); len(got) != 0 {
			t.Fatal("窗口内后续的失败应被压下")
		}
	}
	fail("198.51.100.7")
	fail("198.51.100.7") // 另一个来源也压着一条

	out := c.Offer(&Event{Kind: KindLoginSuccess, Username: "root", SourceIP: "203.0.113.9", Count: 1}, now.Add(3*time.Second))
	if len(out) != 2 || out[0].Kind != KindLoginFailed || out[0].Count != 4 || out[0].SourceIP != "203.0.113.9" ||
		out[1].Kind != KindLoginSuccess {
		t.Fatalf("应先报同来源压着的 4 次失败、再报成功：%+v", out)
	}
	// 别的来源的不受影响，仍在窗口结束时汇总。
	rest := c.Flush(now.Add(coalesceWindow + time.Second))
	if len(rest) != 1 || rest[0].SourceIP != "198.51.100.7" || rest[0].Count != 1 {
		t.Fatalf("另一个来源的汇总应照常在窗口结束时上报：%+v", rest)
	}
}

// 合并表按事件类型分别设上限：不需要凭据就能造的「连接提前断开」占不掉登录失败的位置。
func TestCoalescerTablePerKind(t *testing.T) {
	c := newCoalescer()
	now := time.Unix(1760000000, 0)
	for i := 0; i < coalesceMaxKeys+10; i++ {
		c.Offer(&Event{Kind: KindPreauthClose, Username: "u" + strconv.Itoa(i), SourceIP: "203.0.113.9", Count: 1}, now)
	}
	if got := c.Offer(&Event{Kind: KindLoginFailed, Username: "root", SourceIP: "198.51.100.7", Count: 1}, now); len(got) != 1 {
		t.Fatal("另一类事件的表满了，不该挡住登录失败")
	}
	if got := c.Offer(&Event{Kind: KindSudoDenied, Username: "eve", Reason: "user NOT in sudoers", Count: 1}, now); len(got) != 1 {
		t.Fatal("另一类事件的表满了，不该挡住被拒的 sudo")
	}
	// 窗口结束后位置要还回来。
	c.Flush(now.Add(coalesceWindow + time.Second))
	if n := c.openByKind[KindPreauthClose]; n != 0 {
		t.Fatalf("窗口结束后计数应归零，得 %d", n)
	}
}
