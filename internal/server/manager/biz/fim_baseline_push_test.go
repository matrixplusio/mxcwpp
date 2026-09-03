package biz

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// fakeSender 记录下发的命令，替代真实 ACDispatcher。
type fakeSender struct {
	agentID string
	cmd     *grpcProto.Command
	err     error
	calls   int
}

func (f *fakeSender) SendCommand(agentID string, cmd *grpcProto.Command) error {
	f.calls++
	f.agentID, f.cmd = agentID, cmd
	return f.err
}

func setupFIMDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// 手建表：这几张表的时间列带 MySQL 的 ON UPDATE CURRENT_TIMESTAMP，
	// sqlite 不认，AutoMigrate 会直接失败。
	for _, ddl := range []string{
		`CREATE TABLE fim_baselines (
			tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
			policy_id TEXT, host_id TEXT, hostname TEXT, version INTEGER DEFAULT 1,
			status TEXT DEFAULT 'pending', entry_count INTEGER DEFAULT 0,
			approved_by TEXT, approved_at TIMESTAMP, task_id TEXT,
			created_at TIMESTAMP, updated_at TIMESTAMP)`,
		`CREATE TABLE fim_baseline_entries (
			tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
			baseline_id INTEGER, file_path TEXT, sha256 TEXT, file_size INTEGER,
			file_mode TEXT, uid INTEGER, gid INTEGER, mtime INTEGER)`,
		`CREATE TABLE fim_tasks (
			tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id TEXT, policy_id TEXT, status TEXT, target_type TEXT,
			target_config TEXT, dispatched_host_count INTEGER, completed_host_count INTEGER,
			total_events INTEGER, executed_at TIMESTAMP, completed_at TIMESTAMP,
			created_at TIMESTAMP, updated_at TIMESTAMP)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	db.Create(&model.FIMTask{TaskID: "task-1", PolicyID: "policy-1"})
	db.Create(&model.FIMBaseline{ID: 1, PolicyID: "policy-1", HostID: "host-1", Version: 3, TaskID: "task-1"})
	db.Create(&model.FIMBaselineEntry{BaselineID: 1, FilePath: "/usr/sbin/zramctl",
		SHA256: "old-hash", FileSize: 100, FileMode: "0755", UID: 0, GID: 0, MTime: 1000})
	db.Create(&model.FIMBaselineEntry{BaselineID: 1, FilePath: "/etc/hosts",
		SHA256: "hosts-hash", FileSize: 50, FileMode: "0644"})
	return db
}

func decodeBaseline(t *testing.T, cmd *grpcProto.Command) agentBaseline {
	t.Helper()
	if cmd == nil || len(cmd.Tasks) != 1 {
		t.Fatal("未下发命令")
	}
	if cmd.Tasks[0].DataType != fimBaselineDataType {
		t.Fatalf("DataType = %d，应为 %d（Agent 只在此类型上收基线）",
			cmd.Tasks[0].DataType, fimBaselineDataType)
	}
	var bl agentBaseline
	if err := json.Unmarshal([]byte(cmd.Tasks[0].Data), &bl); err != nil {
		t.Fatalf("Agent 将无法解析下发的基线: %v", err)
	}
	return bl
}

// TestConfirmedChangeIsWrittenIntoBaseline 确认后的新哈希必须进基线。
//
// 不写回就是此前的行为：基线永远停在首扫快照，同一文件每轮都判 changed。
// 一次包升级因此累积出上万条永不收敛的告警。
func TestConfirmedChangeIsWrittenIntoBaseline(t *testing.T) {
	db := setupFIMDB(t)
	fs := &fakeSender{}
	p := NewFIMBaselinePusher(db, fs, zap.NewNop())

	ev := &model.FIMEvent{
		EventID: "e1", HostID: "host-1", TaskID: "task-1",
		FilePath: "/usr/sbin/zramctl", ChangeType: "changed",
		ChangeDetail: model.ChangeDetail{
			HashBefore: "old-hash", HashAfter: "new-hash",
			SizeBefore: "100", SizeAfter: "222",
		},
	}
	if err := p.PushForConfirmedEvent(ev); err != nil {
		t.Fatalf("回写失败: %v", err)
	}
	if fs.agentID != "host-1" {
		t.Errorf("下发给了 %q，应为 host-1", fs.agentID)
	}

	bl := decodeBaseline(t, fs.cmd)
	got := bl.Entries["/usr/sbin/zramctl"]
	if got.SHA256 != "new-hash" {
		t.Errorf("基线里仍是旧哈希 %q——确认没有生效", got.SHA256)
	}
	if got.Size != 222 {
		t.Errorf("size = %d，应为 222", got.Size)
	}
	if got.Mode != "0755" {
		t.Errorf("mode 被清空了：%q。事件未提及的字段必须保留原值", got.Mode)
	}
	if bl.Version != 4 {
		t.Errorf("version = %d，应从 3 递增到 4", bl.Version)
	}
}

// TestUnconfirmedEntriesAreUntouched 确认一条不等于批准全部。
func TestUnconfirmedEntriesAreUntouched(t *testing.T) {
	db := setupFIMDB(t)
	fs := &fakeSender{}
	p := NewFIMBaselinePusher(db, fs, zap.NewNop())

	if err := p.PushForConfirmedEvent(&model.FIMEvent{
		HostID: "host-1", TaskID: "task-1", FilePath: "/usr/sbin/zramctl",
		ChangeType:   "changed",
		ChangeDetail: model.ChangeDetail{HashAfter: "new-hash"},
	}); err != nil {
		t.Fatalf("回写失败: %v", err)
	}

	bl := decodeBaseline(t, fs.cmd)
	if other := bl.Entries["/etc/hosts"]; other.SHA256 != "hosts-hash" {
		t.Errorf("未被确认的 /etc/hosts 也被改动了：%q——一次确认批准了全部变更", other.SHA256)
	}
	if len(bl.Entries) != 2 {
		t.Errorf("基线条目数 = %d，应仍为 2", len(bl.Entries))
	}
}

// TestRemovedFileLeavesBaseline 删除确认后条目要移出基线。
//
// 留着的话文件已不存在、基线仍有记录，下一轮继续报 removed，同样不收敛。
func TestRemovedFileLeavesBaseline(t *testing.T) {
	db := setupFIMDB(t)
	fs := &fakeSender{}
	p := NewFIMBaselinePusher(db, fs, zap.NewNop())

	if err := p.PushForConfirmedEvent(&model.FIMEvent{
		HostID: "host-1", TaskID: "task-1",
		FilePath: "/usr/sbin/zramctl", ChangeType: "removed",
	}); err != nil {
		t.Fatalf("回写失败: %v", err)
	}
	bl := decodeBaseline(t, fs.cmd)
	if _, ok := bl.Entries["/usr/sbin/zramctl"]; ok {
		t.Error("已删除的文件仍留在基线里，下一轮会再报一次 removed")
	}

	var n int64
	db.Model(&model.FIMBaselineEntry{}).Where("file_path = ?", "/usr/sbin/zramctl").Count(&n)
	if n != 0 {
		t.Errorf("服务端基线表仍有 %d 条该路径记录", n)
	}
}

// TestServerBaselinePersistedAfterPush 服务端版本要跟着涨，否则两侧对不上。
func TestServerBaselinePersistedAfterPush(t *testing.T) {
	db := setupFIMDB(t)
	p := NewFIMBaselinePusher(db, &fakeSender{}, zap.NewNop())

	if err := p.PushForConfirmedEvent(&model.FIMEvent{
		HostID: "host-1", TaskID: "task-1", FilePath: "/usr/sbin/zramctl",
		ChangeType:   "changed",
		ChangeDetail: model.ChangeDetail{HashAfter: "new-hash", SizeAfter: "222"},
	}); err != nil {
		t.Fatalf("回写失败: %v", err)
	}

	var bl model.FIMBaseline
	db.First(&bl, 1)
	if bl.Version != 4 {
		t.Errorf("服务端 version = %d，应为 4", bl.Version)
	}
	var e model.FIMBaselineEntry
	db.First(&e, "baseline_id = ? AND file_path = ?", 1, "/usr/sbin/zramctl")
	if e.SHA256 != "new-hash" {
		t.Errorf("服务端基线条目未更新：%q", e.SHA256)
	}
}

// TestPushFailureDoesNotPersist 下发失败就不该改服务端基线。
//
// 先落库再下发的话，下发失败会让服务端认为 Agent 已持有新基线，
// 而 Agent 手里还是旧的——此后永远对不齐。
func TestPushFailureDoesNotPersist(t *testing.T) {
	db := setupFIMDB(t)
	fs := &fakeSender{err: errSendFailed}
	p := NewFIMBaselinePusher(db, fs, zap.NewNop())

	err := p.PushForConfirmedEvent(&model.FIMEvent{
		HostID: "host-1", TaskID: "task-1", FilePath: "/usr/sbin/zramctl",
		ChangeType:   "changed",
		ChangeDetail: model.ChangeDetail{HashAfter: "new-hash"},
	})
	if err == nil {
		t.Fatal("下发失败却返回成功")
	}

	var bl model.FIMBaseline
	db.First(&bl, 1)
	if bl.Version != 3 {
		t.Errorf("下发失败但服务端 version 已推进到 %d，两侧将永久错位", bl.Version)
	}
}

// TestMissingSenderIsReported 未接线时必须报错，不能静默成功。
//
// 静默成功正是这个缺陷最初的形态：确认按钮点了不报错，基线却没动。
func TestMissingSenderIsReported(t *testing.T) {
	p := NewFIMBaselinePusher(setupFIMDB(t), nil, zap.NewNop())
	if err := p.PushForConfirmedEvent(&model.FIMEvent{
		HostID: "host-1", TaskID: "task-1", FilePath: "/x", ChangeType: "changed",
	}); err == nil {
		t.Error("未接线却静默返回成功——正是要修的那种失效")
	}
}

var errSendFailed = errSend{}

type errSend struct{}

func (errSend) Error() string { return "send failed" }
