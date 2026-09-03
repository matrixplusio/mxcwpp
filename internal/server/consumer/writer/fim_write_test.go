package writer

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

func newFIMTestWriter(t *testing.T) (*MySQLWriter, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	// 手写建表：model.FIMEvent 含 MySQL 专属列定义，sqlite 无法 AutoMigrate。
	if err := db.Exec(`CREATE TABLE fim_events (
		tenant_id TEXT DEFAULT 't-default',
		event_id TEXT PRIMARY KEY,
		host_id TEXT NOT NULL,
		hostname TEXT,
		task_id TEXT,
		file_path TEXT NOT NULL,
		change_type TEXT NOT NULL,
		change_detail TEXT,
		severity TEXT,
		category TEXT,
		detected_at DATETIME,
		status TEXT,
		confirmed_by TEXT,
		confirmed_at DATETIME,
		confirm_reason TEXT,
		alert_id INTEGER,
		created_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	return NewMySQLWriter(db, zap.NewNop()), db
}

// fimMsg 构造一条 FIM 事件消息。rawEventID 模拟插件每轮扫描重置的计数器。
func fimMsg(t *testing.T, hostID, taskID, path, rawEventID string, ts int64) *kafka.MQMessage {
	t.Helper()
	body, err := proto.Marshal(&bridge.Record{
		DataType: 6001,
		Data: &bridge.Payload{Fields: map[string]string{
			"event_id":    rawEventID,
			"task_id":     taskID,
			"file_path":   path,
			"change_type": "changed",
			"severity":    "high",
			"category":    "config",
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &kafka.MQMessage{
		DataType:  6001,
		AgentID:   hostID,
		Hostname:  hostID + ".local",
		Body:      body,
		AgentTime: ts,
	}
}

func countFIM(t *testing.T, db *gorm.DB) int {
	t.Helper()
	var n int
	if err := db.Raw(`SELECT COUNT(*) FROM fim_events`).Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestWriteFIMEvent_TwoHostsSameCampaignNoLoss 计划 E-REL-1 的验收条件：
// 两台主机跑同一 campaign，事件零丢。
//
// 插件的 event_id 每轮扫描从 evt-000001 重新开始，原实现直接拿它当全局主键并
// OnConflict DoNothing——两台主机的首个事件同 ID，第二台被静默丢弃且不报错。
func TestWriteFIMEvent_TwoHostsSameCampaignNoLoss(t *testing.T) {
	w, db := newFIMTestWriter(t)
	ts := time.Now().Unix()

	// 同一 campaign：两台主机各自扫描，各产出 3 条事件，计数器都从 1 开始。
	paths := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"}
	for _, host := range []string{"host-a", "host-b"} {
		for i, p := range paths {
			raw := "evt-00000" + string(rune('1'+i))
			if err := w.WriteFIMEvent(fimMsg(t, host, "task-1", p, raw, ts)); err != nil {
				t.Fatalf("host=%s path=%s 写入失败: %v", host, p, err)
			}
		}
	}

	if got := countFIM(t, db); got != 6 {
		t.Fatalf("两主机各 3 条应全部落库，实际 %d 条（差额即被静默丢弃的事件）", got)
	}
}

// TestWriteFIMEvent_RepeatedScansNoLoss 同一主机连续扫描，计数器每轮重置，
// 事件同样不得互相顶掉。
func TestWriteFIMEvent_RepeatedScansNoLoss(t *testing.T) {
	w, db := newFIMTestWriter(t)
	base := time.Now().Unix()

	for scan := 0; scan < 3; scan++ {
		msg := fimMsg(t, "host-a", "task-1", "/etc/passwd", "evt-000001", base+int64(scan*60))
		if err := w.WriteFIMEvent(msg); err != nil {
			t.Fatalf("第 %d 轮写入失败: %v", scan+1, err)
		}
	}
	if got := countFIM(t, db); got != 3 {
		t.Fatalf("三轮扫描应各留一条，实际 %d 条", got)
	}
}

// TestWriteFIMEvent_ReplayIsIdempotent 同一条消息重放只落一行——
// OnConflict DoNothing 原本就是为重放去重而设，修主键不得破坏它。
func TestWriteFIMEvent_ReplayIsIdempotent(t *testing.T) {
	w, db := newFIMTestWriter(t)
	ts := time.Now().Unix()
	msg := fimMsg(t, "host-a", "task-1", "/etc/passwd", "evt-000001", ts)

	for i := 0; i < 3; i++ {
		if err := w.WriteFIMEvent(msg); err != nil {
			t.Fatalf("重放第 %d 次失败: %v", i+1, err)
		}
	}
	if got := countFIM(t, db); got != 1 {
		t.Fatalf("同一消息重放应只落 1 行，实际 %d 行", got)
	}
}
