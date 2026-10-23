package writer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

// fakeBatch 模拟 clickhouse-go 的批次：任一行 Append 失败后整批作废，Send 必然失败。
type fakeBatch struct {
	chdriver.Batch
	conn    *fakeConn
	query   string
	rows    []string
	invalid bool
}

func (b *fakeBatch) Append(v ...any) error {
	if b.invalid {
		return errors.New("batch is invalid")
	}
	// 测试直接 Append 一个字符串时它就是取值；走真实的 flush 函数时，第 1 列是时间，
	// 第 2 列是 host_id（用作行的标识），FIM 的 severity 在第 6 列。
	key, _ := v[0].(string)
	id := key
	if len(v) > 1 {
		id, _ = v[1].(string)
		if len(v) == 9 {
			key, _ = v[5].(string)
		}
	}
	if b.conn.bad[key] {
		b.invalid = true
		return errors.New("unknown element " + key)
	}
	b.rows = append(b.rows, id)
	return nil
}

func (b *fakeBatch) Abort() error { return nil }

func (b *fakeBatch) Send() error {
	if b.invalid {
		return errors.New("batch is invalid")
	}
	if b.conn.sendErr != nil {
		return b.conn.sendErr
	}
	if b.conn.gate != nil {
		<-b.conn.gate
	}
	b.conn.mu.Lock()
	defer b.conn.mu.Unlock()
	b.conn.sends++
	if n := len(b.rows); n > b.conn.maxBatch {
		b.conn.maxBatch = n
	}
	if b.conn.failOnly == "" || strings.Contains(b.query, b.conn.failOnly) {
		if b.conn.failSends > 0 {
			b.conn.failSends--
			return errors.New("injected: clickhouse unavailable")
		}
		if b.conn.failEvery > 0 && b.conn.sends%b.conn.failEvery == 0 {
			return errors.New("injected: clickhouse flapping")
		}
	}
	b.conn.sent = append(b.conn.sent, b.rows...)
	return nil
}

type fakeConn struct {
	chdriver.Conn
	bad       map[string]bool
	sendErr   error
	failSends int    // 接下来这么多次 Send 失败
	failEvery int    // 每第 N 次 Send 失败（模拟抖动）
	failOnly  string // 非空时只让 INSERT 语句含此串（表名）的 Send 失败
	sends     int
	maxBatch  int           // 单次 Send 最多带了多少行
	gate      chan struct{} // 非空时 Send 先等它（模拟写入很慢）
	mu        sync.Mutex    // 保护 sent 等发送结果，供并发测试读取
	sent      []string
	prepares  int
}

func (c *fakeConn) PrepareBatch(_ context.Context, query string, _ ...chdriver.PrepareBatchOption) (chdriver.Batch, error) {
	c.prepares++
	return &fakeBatch{conn: c, query: query}, nil
}

func newSendTestWriter(conn *fakeConn) *ClickHouseWriter {
	// 不经构造函数：它在 conn 非空时会起后台 flusher 并执行建表。
	return &ClickHouseWriter{
		conn:        conn,
		logger:      zap.NewNop(),
		batchSize:   1000,
		rejects:     rejectLog{last: map[string]time.Time{}, suppressed: map[string]int{}},
		retrySince:  map[string]time.Time{},
		room:        make(chan struct{}),
		maxBuffered: defaultMaxBuffered,
		maxRetained: defaultMaxBuffered / 2,
		flushCh:     make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
}

func sendSeverities(w *ClickHouseWriter, table string, rows []string) bool {
	ok, _ := w.sendRows(table, "INSERT", len(rows), nil, func(b chdriver.Batch, i int) error {
		return b.Append(rows[i])
	})
	return ok
}

// 一行取值不合表结构，只丢这一行；同批的 critical 必须照常落盘。
// 改之前整批作废——FIM 的 info 行就是这样把同批的 critical 变更一起带走的。
func TestSendRowsSkipsRejectedRowAndKeepsTheRest(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{"info": true}}
	w := newSendTestWriter(conn)
	before := testutil.ToFloat64(consumermetrics.CHRowsRejectedTotal.WithLabelValues("t_skip"))

	ok := sendSeverities(w, "t_skip", []string{"critical", "info", "high", "info", "critical"})

	if !ok {
		t.Fatal("只有个别行被拒时应视为处理完成")
	}
	if got := len(conn.sent); got != 3 {
		t.Fatalf("应写入 3 行，实际 %d: %v", got, conn.sent)
	}
	if _, pending := w.retrySince["t_skip"]; pending {
		t.Error("被拒的行重试也写不进去，不应标记待重试卡住 offset")
	}
	if got := testutil.ToFloat64(consumermetrics.CHRowsRejectedTotal.WithLabelValues("t_skip")) - before; got != 2 {
		t.Errorf("拒收计数应为 2，实际 %v", got)
	}
}

// 整批都被拒：没有可写的行，不发送也不算失败。
func TestSendRowsAllRejected(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{"info": true}}
	w := newSendTestWriter(conn)

	if !sendSeverities(w, "t_all", []string{"info", "info"}) {
		t.Fatal("全部被拒时应视为处理完成")
	}
	if len(conn.sent) != 0 {
		t.Errorf("不应写入任何行: %v", conn.sent)
	}
}

// 被拒行超过上限：是整类数据与表结构不符，按整批失败处理，置失败标记。
func TestSendRowsTooManyRejectsFailsBatch(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{"info": true}}
	w := newSendTestWriter(conn)
	rows := make([]string, 0, maxRejectsPerBatch+5)
	for i := 0; i < maxRejectsPerBatch+5; i++ {
		rows = append(rows, "info")
	}
	rows = append(rows, "critical")

	if sendSeverities(w, "t_many", rows) {
		t.Fatal("超过拒收上限应按整批失败")
	}
	if conn.prepares > maxRejectsPerBatch+2 {
		t.Errorf("超过上限后应停止重建批次，实际重建 %d 次", conn.prepares)
	}
}

// 已知的坏取值在进批次前剔除：不触发重建（每次重建都要断开重连），好行照常写入，
// 坏行再多也不会因为上限把同批的好行一起丢掉。
func TestSendRowsValidatorRejectsWithoutRebuild(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{"bogus": true}}
	w := newSendTestWriter(conn)
	rows := []string{"critical"}
	for i := 0; i < maxRejectsPerBatch*3; i++ {
		rows = append(rows, "bogus")
	}
	rows = append(rows, "high")

	ok, _ := w.sendRows("t_valid", "INSERT", len(rows), func(i int) error {
		if rows[i] == "bogus" {
			return errors.New("not in enum")
		}
		return nil
	}, func(b chdriver.Batch, i int) error { return b.Append(rows[i]) })

	if !ok {
		t.Fatal("预检剔除后应正常完成")
	}
	if conn.prepares != 1 {
		t.Errorf("预检剔除不应重建批次，实际建了 %d 次", conn.prepares)
	}
	if len(conn.sent) != 2 {
		t.Errorf("两行好数据都应写入，实际 %v", conn.sent)
	}
}

// 全部被预检剔除时不去建批次（建批次要占一条连接）。
func TestSendRowsAllRejectedByValidatorSkipsPrepare(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}}
	w := newSendTestWriter(conn)
	ok, _ := w.sendRows("t_none", "INSERT", 2, func(int) error { return errors.New("x") },
		func(b chdriver.Batch, i int) error { return b.Append("high") })
	if !ok || conn.prepares != 0 {
		t.Errorf("全部剔除时应直接完成、不建批次，ok=%v prepares=%d", ok, conn.prepares)
	}
}

// FIM 枚举预检与表定义一致：info 必须放行（1.0.2 起的包管理器变更），未知值必须剔除。
func TestFIMEnumSetsMatchSchema(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		if !fimSeverities[s] {
			t.Errorf("severity %q 应合法", s)
		}
	}
	if fimSeverities[""] || fimSeverities["warning"] {
		t.Error("不在枚举里的 severity 应被剔除")
	}
	if !strings.Contains(fimSeverityNewType, "'info' = 0") {
		t.Error("新列类型应包含 info")
	}
}

// 发送本身失败（ClickHouse 不可用）仍按原语义置失败标记。
func TestSendRowsSendFailureMarksFlag(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{}, sendErr: errors.New("connection refused")}
	w := newSendTestWriter(conn)

	if sendSeverities(w, "t_down", []string{"high"}) {
		t.Fatal("发送失败应返回 false")
	}
}

// 代码里的新列类型与建表脚本必须一致，否则启动检查会把新装环境当成「类型不符」。
func TestFIMSeverityTypeMatchesInitSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "init-clickhouse.sql"))
	if err != nil {
		t.Skipf("读取建表脚本失败: %v", err)
	}
	strip := func(s string) string { return strings.ReplaceAll(s, " ", "") }
	if !strings.Contains(strip(string(data)), "severityEnum8"+strings.TrimPrefix(strip(fimSeverityNewType), "Enum8")) {
		t.Errorf("deploy/init-clickhouse.sql 里 fim_events.severity 与 %s 不一致", fimSeverityNewType)
	}
}

// 启动时没能把 info 补进表的枚举，info 行要在预检阶段剔除，不能进批次逐行断连重建。
func TestFIMInfoRejectedWhenSchemaNotUpgraded(t *testing.T) {
	conn := &fakeConn{bad: map[string]bool{"info": true}}
	w := newSendTestWriter(conn)
	rows := []fimEventRow{{Severity: "critical", ChangeType: "changed"}}
	for i := 0; i < maxRejectsPerBatch*2; i++ {
		rows = append(rows, fimEventRow{Severity: "info", ChangeType: "changed"})
	}
	if ok, _ := w.flushFIMEvents(rows); !ok {
		t.Fatal("未补齐枚举时 info 行应被预检剔除，批次本身应成功")
	}
	if conn.prepares != 1 || len(conn.sent) != 1 {
		t.Errorf("应只建一次批次、只写 critical 一行，实际 prepares=%d sent=%v", conn.prepares, conn.sent)
	}

	w.fimInfoOK.Store(true)
	conn2 := &fakeConn{bad: map[string]bool{}}
	w.conn = conn2
	if ok, _ := w.flushFIMEvents(rows); !ok || len(conn2.sent) != len(rows) {
		t.Errorf("枚举已含 info 时全部行都应写入，实际 %d/%d", len(conn2.sent), len(rows))
	}
}
