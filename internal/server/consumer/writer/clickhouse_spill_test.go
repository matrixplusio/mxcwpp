package writer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

// fakeSpiller 记录转存的记录；err 非空时转存失败。
type fakeSpiller struct {
	mu      sync.Mutex
	records []SpillRecord
	err     error
}

func (s *fakeSpiller) Spill(rs []SpillRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, rs...)
	return nil
}

func (s *fakeSpiller) hostIDs(t *testing.T) []string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, r := range s.records {
		var rows []fimEventRow
		if err := json.Unmarshal(r.Rows, &rows); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			ids = append(ids, row.HostID)
		}
	}
	return ids
}

// 一张表持续写不进去超过 spillAfter，积压转存后放行 offset——不能无限期拦住整个 consumer。
func TestPersistentFailureSpillsAndReleases(t *testing.T) {
	old := spillAfter
	spillAfter = 0
	defer func() { spillAfter = old }()

	conn := &fakeConn{bad: map[string]bool{}, failSends: 1000}
	sp := &fakeSpiller{}
	w := newSendTestWriter(conn)
	w.SetSpiller(sp)
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b")}

	if err := w.Flush(); err != nil {
		t.Fatalf("转存成功后应放行 offset: %v", err)
	}
	if len(w.fimRows) != 0 {
		t.Errorf("转存后缓冲应清空，实际 %d 行", len(w.fimRows))
	}
	if got := fmt.Sprint(sp.hostIDs(t)); got != "[a b]" {
		t.Errorf("转存内容应为 [a b]，实际 %s", got)
	}
	if sp.records[0].Reason != SpillReasonUnavailable || sp.records[0].Table != "fim_events" {
		t.Errorf("转存记录的表或原因不对: %+v", sp.records[0])
	}
}

// 未到 spillAfter 前只重试、不转存：一次抖动不应把数据转存出去要人工回放。
func TestShortFailureRetriesWithoutSpilling(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 1}
	sp := &fakeSpiller{}
	w := newSendTestWriter(conn)
	w.SetSpiller(sp)
	w.fimRows = []fimEventRow{fimRow("a")}

	if w.Flush() == nil {
		t.Fatal("第一次失败应拦住 offset")
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("恢复后应放行: %v", err)
	}
	if len(sp.records) != 0 {
		t.Errorf("短暂失败不应转存，实际转存 %d 条", len(sp.records))
	}
}

// 转存也失败：数据留在内存里，offset 不放行。
func TestSpillFailureKeepsRows(t *testing.T) {
	old := spillAfter
	spillAfter = 0
	defer func() { spillAfter = old }()

	conn := &fakeConn{bad: map[string]bool{}, failSends: 1000}
	w := newSendTestWriter(conn)
	w.SetSpiller(&fakeSpiller{err: errors.New("kafka down")})
	w.fimRows = []fimEventRow{fimRow("a")}

	if w.Flush() == nil {
		t.Fatal("ClickHouse 与转存都失败时必须拦住 offset")
	}
	if len(w.fimRows) != 1 {
		t.Errorf("行必须留在缓冲里，实际 %d 行", len(w.fimRows))
	}
}

// 被拒收的行有转存器时转存，不丢；补好表结构后可回放。
func TestRejectedRowsAreSpilled(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}}
	sp := &fakeSpiller{}
	w := newSendTestWriter(conn)
	w.SetSpiller(sp)
	w.fimRows = []fimEventRow{fimRow("good"), {HostID: "bad", Severity: "bogus", ChangeType: "changed"}}

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(conn.sent) != "[good]" {
		t.Errorf("好行应写入，实际 %v", conn.sent)
	}
	if got := fmt.Sprint(sp.hostIDs(t)); got != "[bad]" || sp.records[0].Reason != SpillReasonRejected {
		t.Errorf("被拒收的行应以 rejected 原因转存，实际 %s %+v", got, sp.records)
	}
}

// 积压再多，单次写入也不超过 batchSize：大批次更容易超时，超时整批重试会自我放大。
func TestFlushChunksByBatchSize(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failSends: 1}
	w := newSendTestWriter(conn)
	w.batchSize = 10
	for i := 0; i < 35; i++ {
		w.fimRows = append(w.fimRows, fimRow(fmt.Sprint(i)))
	}
	_ = w.Flush()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if conn.maxBatch > 10 {
		t.Errorf("单次写入不应超过 batchSize=10，实际 %d", conn.maxBatch)
	}
	if len(conn.sent) != 35 {
		t.Errorf("应写入 35 行，实际 %d", len(conn.sent))
	}
}

// 正在写的行计入背压上限：否则刷盘期间缓冲看起来是空的，写入方会再灌满一整份上限。
func TestInflightRowsCountTowardBackpressure(t *testing.T) {
	gate := make(chan struct{})
	conn := &fakeConn{bad: map[string]bool{}, gate: gate}
	w := newSendTestWriter(conn)
	w.maxBuffered = 2
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b")}

	flushed := make(chan struct{})
	go func() { w.flush(); close(flushed) }()
	time.Sleep(50 * time.Millisecond) // 让刷盘取走两行、卡在 Send

	wrote := make(chan struct{})
	go func() { _ = w.WriteFIMEvent(&kafka.MQMessage{AgentID: "c"}); close(wrote) }()
	select {
	case <-wrote:
		t.Fatal("两行正在写，已达上限，写入方应等待")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	<-flushed
	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("写完后写入方应被放行")
	}
}

// 真并发：写入方、周期刷盘、提交屏障同时跑，ClickHouse 间歇失败。屏障每次放行时，
// 它快照里的每一行都必须已经落盘——这是 offset 提交的前提。去掉 flushMu 这个测试会失败。
func TestBarrierInvariantUnderConcurrency(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, failEvery: 4}
	w := newSendTestWriter(conn)
	w.batchSize = 20

	var pmu sync.Mutex
	var processed []string
	stop := make(chan struct{})
	var bg sync.WaitGroup

	bg.Add(1)
	go func() { // 周期刷盘
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				w.flush()
			}
		}
	}()
	violations := 0
	bg.Add(1)
	go func() { // 提交屏障：先快照已处理，再刷盘
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			pmu.Lock()
			snap := append([]string(nil), processed...)
			pmu.Unlock()
			if w.Flush() != nil {
				continue
			}
			conn.mu.Lock()
			sent := make(map[string]bool, len(conn.sent))
			for _, id := range conn.sent {
				sent[id] = true
			}
			conn.mu.Unlock()
			for _, id := range snap {
				if !sent[id] {
					violations++
					break
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				id := fmt.Sprintf("%d-%d", g, i)
				_ = w.WriteEBPFEvent(&kafka.MQMessage{AgentID: id})
				pmu.Lock()
				processed = append(processed, id)
				pmu.Unlock()
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	bg.Wait()
	if violations > 0 {
		t.Fatalf("屏障放行了 %d 次快照里仍有未落盘的行", violations)
	}
}

// 转存出去的记录能原样写回：回放工具靠这条路径补数据。
func TestReplaySpillRoundTrip(t *testing.T) {
	old := spillAfter
	spillAfter = 0
	defer func() { spillAfter = old }()

	sp := &fakeSpiller{}
	w := newSendTestWriter(&fakeConn{bad: map[string]bool{}, failSends: 1000})
	w.SetSpiller(sp)
	w.fimRows = []fimEventRow{fimRow("a"), fimRow("b")}
	w.ebpfRows = []ebpfEventRow{{HostID: "e1"}}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	target := &fakeConn{bad: map[string]bool{}}
	r := newSendTestWriter(target)
	total := 0
	for _, rec := range sp.records {
		n, rej, err := r.ReplaySpill(rec)
		if err != nil || rej != 0 {
			t.Fatalf("回放失败: %v rejected=%d", err, rej)
		}
		total += n
	}
	if total != 3 || len(target.sent) != 3 {
		t.Errorf("应回放 3 行，实际 %d / %v", total, target.sent)
	}
	if _, _, err := r.ReplaySpill(SpillRecord{Table: "nope", Rows: []byte("[]")}); err == nil {
		t.Error("未知的表应报错")
	}
}

// 一行既写不进 ClickHouse 又大到转存不了（失陷主机可以故意构造），只隔离这一行，
// 不能让它把整个 consumer 的 offset 永久拦住。
func TestOversizeRejectedRowIsIsolated(t *testing.T) {
	sp := &fakeSpiller{}
	w := newSendTestWriter(&fakeConn{bad: map[string]bool{}})
	w.SetSpiller(sp)
	huge := fimEventRow{HostID: "evil", Severity: "bogus", ChangeType: "changed", Detail: strings.Repeat("<", 2<<20)}
	w.fimRows = []fimEventRow{fimRow("good"), huge}
	before := testutil.ToFloat64(consumermetrics.CHRowsDroppedTotal.WithLabelValues("fim_events"))

	if err := w.Flush(); err != nil {
		t.Fatalf("过大的坏行应被隔离，不能拦住 offset: %v", err)
	}
	if testutil.ToFloat64(consumermetrics.CHRowsDroppedTotal.WithLabelValues("fim_events"))-before != 1 {
		t.Error("隔离丢弃应计数")
	}
	if fmt.Sprint(conn(w).sent) != "[good]" {
		t.Errorf("好行应写入，实际 %v", conn(w).sent)
	}
}

func conn(w *ClickHouseWriter) *fakeConn { return w.conn.(*fakeConn) }

// 转存按字节切块，每条消息都远小于 Kafka 的 4MB 上限；< > & 不做 6 倍转义。
func TestSpillChunksByBytes(t *testing.T) {
	sp := &fakeSpiller{}
	w := newSendTestWriter(&fakeConn{bad: map[string]bool{}})
	w.SetSpiller(sp)
	var rows []fimEventRow
	for i := 0; i < 10; i++ {
		rows = append(rows, fimEventRow{HostID: fmt.Sprint(i), Severity: "high", ChangeType: "changed", Detail: strings.Repeat("<", 300<<10)})
	}
	if err := spillRows(w, "fim_events", SpillReasonUnavailable, rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range sp.records {
		if len(r.Rows) > spillRecordBytes+2 {
			t.Errorf("单条转存记录 %d 字节，超过上限", len(r.Rows))
		}
	}
	if got := len(sp.hostIDs(t)); got != 10 {
		t.Errorf("10 行都应转存，实际 %d", got)
	}
}

// NaN/Inf 解析为 0：否则 ClickHouse 宕机时这张表永远转存不出去。
func TestParseFloat32RejectsNaNInf(t *testing.T) {
	for _, s := range []string{"NaN", "nan", "Inf", "-Inf", "+Inf"} {
		if v := parseFloat32(s); v != 0 {
			t.Errorf("parseFloat32(%q) = %v，应为 0", s, v)
		}
	}
	if parseFloat32("1.5") != 1.5 {
		t.Error("正常数值应原样解析")
	}
}

// 回放认证日志时重做截断与脱敏：转存主题没有鉴权，内容不可信。
func TestAuthRowNormalizeOnReplay(t *testing.T) {
	r := authEventRow{Command: "mysql -uroot --password=hunter2", Username: strings.Repeat("u", authFieldMaxLen+10)}
	r.normalize()
	if strings.Contains(r.Command, "hunter2") {
		t.Errorf("命令行里的口令应被脱敏: %s", r.Command)
	}
	if len(r.Username) != authFieldMaxLen {
		t.Errorf("字段应截断到 %d，实际 %d", authFieldMaxLen, len(r.Username))
	}
}

// Close 等最终刷盘完成才返回：之后关闭转存器才不会撞上还在进行的转存。
func TestCloseWaitsForFinalFlush(t *testing.T) {
	gate := make(chan struct{})
	c := &fakeConn{bad: map[string]bool{}, gate: gate}
	w := newSendTestWriter(c)
	w.flushTimeout = time.Hour
	w.flusherDone = make(chan struct{})
	w.fimRows = []fimEventRow{fimRow("last")}
	go w.flusher()

	closed := make(chan struct{})
	go func() { w.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("最终刷盘还卡在发送，Close 不应返回")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("最终刷盘完成后 Close 应返回")
	}
	if fmt.Sprint(c.sent) != "[last]" {
		t.Errorf("最终刷盘应写入 last，实际 %v", c.sent)
	}
}
