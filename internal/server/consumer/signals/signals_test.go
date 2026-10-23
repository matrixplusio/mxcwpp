package signals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// fakeSession 只记录 MarkOffset 与 Commit。
type fakeSession struct {
	mu      sync.Mutex
	marked  map[int32]int64
	commits int
}

func (f *fakeSession) Claims() map[string][]int32 { return nil }
func (f *fakeSession) MemberID() string           { return "" }
func (f *fakeSession) GenerationID() int32        { return 0 }
func (f *fakeSession) MarkOffset(_ string, p int32, off int64, _ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.marked == nil {
		f.marked = map[int32]int64{}
	}
	f.marked[p] = off
}
func (f *fakeSession) Commit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits++
}
func (f *fakeSession) ResetOffset(string, int32, int64, string)    {}
func (f *fakeSession) MarkMessage(*sarama.ConsumerMessage, string) {}
func (f *fakeSession) Context() context.Context                    { return context.Background() }

func msg(p int32, off int64, value string) *sarama.ConsumerMessage {
	return &sarama.ConsumerMessage{Topic: "mxcwpp.engine.alert", Partition: p, Offset: off, Value: []byte(value)}
}

const celHit = `{"host_id":"h1","rule_id":"72","stage":"cel_rule","severity":"medium",
	"detected_at":"2026-10-22T01:03:04Z","attck_technique":"T1059.004",
	"payload":{"rule_name":"/tmp 目录可执行文件创建","matched_fields":{"exe":"/usr/bin/dnf","parent_exe":"/usr/bin/python3","cmdline":"dnf -y update --password=hunter2"}}}`

func TestParseCELHit(t *testing.T) {
	r, result := parse([]byte(celHit))
	if result != "ok" || r == nil {
		t.Fatalf("应解析成功，得 %s", result)
	}
	if r.RuleID != "cel-72" || r.Stage != "cel_rule" || r.RuleName != "/tmp 目录可执行文件创建" {
		t.Fatalf("规则信息不对: %+v", r)
	}
	if r.Exe != "/usr/bin/dnf" || r.ParentExe != "/usr/bin/python3" || r.Tactic != "TA0002" {
		t.Fatalf("进程或战术不对: %+v", r)
	}
	if strings.Contains(r.Cmdline, "hunter2") {
		t.Fatalf("命令行里的口令应被遮蔽: %q", r.Cmdline)
	}
	if !r.Bucket.Equal(time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("应落在 01:00 的 10 分钟桶，得 %s", r.Bucket)
	}
}

func TestParseOtherShapes(t *testing.T) {
	seq, _ := parse([]byte(`{"host_id":"h1","rule_id":"3","stage":"sequence","payload":{"matched_fields":{"exe":"/usr/bin/sudo"}}}`))
	if seq.RuleID != "seq-3" || seq.Exe != "/usr/bin/sudo" {
		t.Fatalf("攻击链规则号应换成 seq-N: %+v", seq)
	}
	ev, _ := parse([]byte(`{"host_id":"h1","rule_id":"ROOTKIT_BACKDOOR","stage":"anti_rootkit","payload":{"evidence":{"exe":"/tmp/x"}}}`))
	if ev.RuleID != "ROOTKIT_BACKDOOR" || ev.Exe != "/tmp/x" {
		t.Fatalf("evidence 里的字段应取到: %+v", ev)
	}
	top, _ := parse([]byte(`{"host_id":"h1","rule_id":"WEBSHELL_HEURISTIC","stage":"webshell","payload":{"exe":"/usr/sbin/php-fpm"}}`))
	if top.Exe != "/usr/sbin/php-fpm" {
		t.Fatalf("顶层字段应取到: %+v", top)
	}
	if _, result := parse([]byte(`not json`)); result != "decode_error" {
		t.Fatalf("坏消息应记 decode_error，得 %s", result)
	}
	if _, result := parse([]byte(`{"rule_id":"1"}`)); result != "no_host" {
		t.Fatalf("没有主机应记 no_host，得 %s", result)
	}
}

// 同一个键在同一个 10 分钟桶里合并成一行，写入成功后才提交 offset。
func TestFlushMergesAndCommitsAfterWrite(t *testing.T) {
	s := New(nil, zap.NewNop())
	var written []*row
	s.insert = func(_ context.Context, rows []*row) error { written = append(written, rows...); return nil }
	for i := int64(0); i < 5; i++ {
		s.add(msg(2, 100+i, celHit))
	}
	s.add(msg(3, 7, `not json`)) // 坏消息不产生行，但不能卡住 offset
	sess := &fakeSession{}
	s.flush(sess)
	if len(written) != 1 || written[0].Hits != 5 {
		t.Fatalf("应合并成 1 行 5 次命中，得 %d 行", len(written))
	}
	if sess.marked[2] != 105 || sess.marked[3] != 8 || sess.commits != 1 {
		t.Fatalf("写入后应提交到下一条 offset: %+v commits=%d", sess.marked, sess.commits)
	}
}

// 写失败时不提交 offset，数据留在内存里，下次一起写。
func TestFlushFailureKeepsRowsAndOffsets(t *testing.T) {
	s := New(nil, zap.NewNop())
	fail := true
	var written []*row
	s.insert = func(_ context.Context, rows []*row) error {
		if fail {
			return errors.New("clickhouse down")
		}
		written = append(written, rows...)
		return nil
	}
	s.add(msg(0, 10, celHit))
	sess := &fakeSession{}
	s.flush(sess)
	if len(sess.marked) != 0 || sess.commits != 0 {
		t.Fatalf("写失败不应提交 offset: %+v", sess.marked)
	}
	s.add(msg(0, 11, celHit))
	fail = false
	s.flush(sess)
	if len(written) != 1 || written[0].Hits != 2 || sess.marked[0] != 12 {
		t.Fatalf("重试时应连同上次未写入的一起写: rows=%d marked=%v", len(written), sess.marked)
	}
}

func TestFullStopsConsumption(t *testing.T) {
	s := New(nil, zap.NewNop())
	for i := 0; i < maxKeys; i++ {
		s.rows[key{bucket: int64(i)}] = &row{}
	}
	if !s.full() {
		t.Fatal("达到上限应暂停消费")
	}
}

// 一台主机用随机路径反复执行程序造键：超过单主机上限后并进 overflow，命中次数不丢，也不会占满全局。
func TestPerHostKeyLimit(t *testing.T) {
	s := New(nil, zap.NewNop())
	base := time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)
	for i := 0; i < perHostMaxKeys+500; i++ {
		s.mu.Lock()
		s.mergeLocked(&row{Bucket: base, HostID: "noisy", Stage: "cel_rule", RuleID: "cel-1",
			Exe: fmt.Sprintf("/tmp/r%d", i), Cmdline: "x", Hits: 1, FirstSeen: base, LastSeen: base})
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.mergeLocked(&row{Bucket: base, HostID: "quiet", Stage: "cel_rule", RuleID: "cel-1", Exe: "/usr/bin/a", Hits: 1, FirstSeen: base, LastSeen: base})
	s.mu.Unlock()

	var total uint32
	var overflow *row
	for k, r := range s.rows {
		if k.host == "noisy" {
			total += r.Hits
		}
		if k.exe == overflowExe {
			overflow = r
		}
	}
	if len(s.rows) != perHostMaxKeys+2 || overflow == nil || overflow.Hits != 500 || overflow.Cmdline != "" {
		t.Fatalf("超出上限的命中应并进一个 overflow 键: keys=%d overflow=%+v", len(s.rows), overflow)
	}
	if total != perHostMaxKeys+500 {
		t.Fatalf("命中次数不能丢，得 %d", total)
	}
}
