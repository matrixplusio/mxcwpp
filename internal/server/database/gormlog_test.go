package database

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newObservedWriter(t *testing.T) (*zapWriter, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	return &zapWriter{logger: zap.New(core)}, logs
}

// TestZapWriter_TruncatesOversizedStatements GORM 报错时会把完整 SQL 交给 Writer，
// 批量 INSERT 语句可达数 KB。单条必须有上限。
//
// 回归 2026-08：alerts 表写满后每条失败重试都打印完整 INSERT（约 1.5KB），
// 单日 20GB 写满 node1 根盘。
func TestZapWriter_TruncatesOversizedStatements(t *testing.T) {
	w, logs := newObservedWriter(t)

	huge := "INSERT INTO `alerts` " + strings.Repeat("x", 8000)
	w.Printf("%s", huge)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("应写出 1 条日志，实际 %d", len(entries))
	}
	msg := entries[0].Message
	if len(msg) >= len(huge) {
		t.Errorf("超长语句未被截断：原长 %d，写出 %d", len(huge), len(msg))
	}
	if !strings.Contains(msg, "截断") {
		t.Error("截断后应说明原长，否则看日志的人不知道内容被裁了")
	}
	if !strings.HasPrefix(msg, "INSERT INTO `alerts`") {
		t.Error("截断应保留开头——错误定位靠的是语句前缀，不是结尾")
	}
}

// TestZapWriter_RateLimitsBurst 高频写入必须被限速，否则截断也挡不住总量。
func TestZapWriter_RateLimitsBurst(t *testing.T) {
	w, logs := newObservedWriter(t)

	const burst = gormLogMaxPerSec * 10
	for range burst {
		w.Printf("Error 1114 (HY000): The table 'alerts' is full")
	}

	got := logs.Len()
	if got > gormLogMaxPerSec {
		t.Errorf("单秒内应最多放行 %d 条，实际 %d —— 限速未生效", gormLogMaxPerSec, got)
	}
	if got == 0 {
		t.Error("限速不应把日志全部吞掉，问题会因此完全不可见")
	}
}

// TestZapWriter_ReportsSuppressedCount 被丢弃的条数必须带出来。
//
// 否则限速之后"日志变少了"看起来就像"问题消失了"——这比日志太多更危险。
func TestZapWriter_ReportsSuppressedCount(t *testing.T) {
	w, logs := newObservedWriter(t)

	for range gormLogMaxPerSec * 3 {
		w.Printf("boom")
	}

	// 推进到下一个窗口，让后续日志得以放行并带出抑制计数
	w.mu.Lock()
	w.windowStart = time.Now().Add(-2 * gormLogWindowSpan)
	w.mu.Unlock()
	w.Printf("next window")

	last := logs.All()[logs.Len()-1]
	if last.Level != zapcore.WarnLevel {
		t.Errorf("带抑制计数的日志应升为 warn 以便被看见，实际 %v", last.Level)
	}
	var found bool
	for _, f := range last.Context {
		if f.Key == "suppressed_since_last" && f.Integer > 0 {
			found = true
		}
	}
	if !found {
		t.Error("应带 suppressed_since_last 字段说明期间丢了多少条")
	}
}

// TestZapWriter_NormalTrafficUnaffected 正常低频日志不受影响：不截断、不降级、不丢。
func TestZapWriter_NormalTrafficUnaffected(t *testing.T) {
	w, logs := newObservedWriter(t)

	const msg = "SLOW SQL >= 200ms: SELECT * FROM hosts WHERE status = 'online'"
	w.Printf("%s", msg)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("应写出 1 条，实际 %d", len(entries))
	}
	if entries[0].Message != msg {
		t.Errorf("正常长度的日志不应被改动，得到 %q", entries[0].Message)
	}
	if entries[0].Level != zapcore.InfoLevel {
		t.Errorf("无抑制发生时应保持 info 级，实际 %v", entries[0].Level)
	}
}

// TestZapWriter_WindowResets 限速是滑动窗口而非一次性配额，下个窗口必须恢复放行。
func TestZapWriter_WindowResets(t *testing.T) {
	w, logs := newObservedWriter(t)

	for range gormLogMaxPerSec * 2 {
		w.Printf("first window")
	}
	firstCount := logs.Len()

	w.mu.Lock()
	w.windowStart = time.Now().Add(-2 * gormLogWindowSpan)
	w.mu.Unlock()

	for range gormLogMaxPerSec {
		w.Printf("second window")
	}
	if logs.Len() <= firstCount {
		t.Error("新窗口应重新放行日志，否则一次突发会永久静音")
	}
}
