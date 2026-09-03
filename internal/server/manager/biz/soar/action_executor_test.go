package soar

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newTestExecutor(t *testing.T) (*DefaultActionExecutor, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.HostIsolation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// acDispatcher 非 nil 才会走到"未接线"分支；nil 时是另一条明确的错误路径。
	return &DefaultActionExecutor{db: db, acDispatcher: &sd.ACDispatcher{}, logger: zap.NewNop()}, db
}

// TestUnwiredActionsReportFailure 未接线的处置动作必须报错，绝不能返回 success。
//
// 原实现让这些动作 return nil，于是 Playbook 记 success、界面显示"已处置"，而命令
// 从未到达主机。安全产品里这是最坏的失败模式：值班看到"已阻断"就停止响应。
func TestUnwiredActionsReportFailure(t *testing.T) {
	exec, _ := newTestExecutor(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		kind   ActionKind
		params map[string]interface{}
	}{
		{"kill_pid", ActionKillPID, map[string]interface{}{"host_id": "h-1", "pid": float64(1234)}},
		{"block_ip", ActionBlockIP, map[string]interface{}{"host_id": "h-1", "ip": "10.0.0.1"}},
		{"quarantine_file", ActionQuarantineFile, map[string]interface{}{"host_id": "h-1", "path": "/tmp/x"}},
		{"disable_user", ActionDisableUser, map[string]interface{}{"host_id": "h-1", "username": "attacker"}},
		{"revoke_ssh_key", ActionRevokeSSHKey, map[string]interface{}{"host_id": "h-1", "username": "root", "key_fingerprint": "SHA256:abc"}},
		{"snapshot_forensic", ActionSnapshotForensic, map[string]interface{}{"host_id": "h-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := exec.Execute(ctx, c.kind, c.params, &ExecutionContext{Operator: "soar"})
			if err == nil {
				t.Fatalf("未接线动作应报错，实际返回成功: out=%v", out)
			}
			if !errors.Is(err, ErrActionNotImplemented) {
				t.Errorf("错误应可判定为未接线（errors.Is ErrActionNotImplemented），实际: %v", err)
			}
			if out != nil {
				t.Errorf("失败时不应返回结果载荷，实际: %v", out)
			}
		})
	}
}

// TestIsolateHostNeverRecordsFalseState 下发失败时隔离记录不得停留在 active。
//
// 原实现把下发失败降级为 warning，保留 status="isolated" 的记录并返回成功——
// 平台会显示主机已隔离而实际没有。且 "isolated" 根本不在 model.HostIsolation
// 定义的状态机内，status='active' 查询压根找不到它。
func TestIsolateHostNeverRecordsFalseState(t *testing.T) {
	exec, db := newTestExecutor(t)

	out, err := exec.Execute(context.Background(), ActionIsolateHost,
		map[string]interface{}{"host_id": "h-1", "reason": "test"}, &ExecutionContext{Operator: "soar"})
	if err == nil {
		t.Fatalf("下发未接线时隔离动作应失败，实际成功: %v", out)
	}

	var records []model.HostIsolation
	if err := db.Find(&records).Error; err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("应留下 1 条记录用于追溯，实际 %d 条", len(records))
	}
	if records[0].Status != isolationStatusFailed {
		t.Errorf("下发失败后状态应为 %q，实际 %q（不得对外宣称已隔离）",
			isolationStatusFailed, records[0].Status)
	}
}

// TestIsolateHostStatusIsInStateMachine 写入的状态必须取自模型定义的状态机。
func TestIsolateHostStatusIsInStateMachine(t *testing.T) {
	valid := map[string]bool{"pending": true, "active": true, "released": true, "failed": true}
	for _, s := range []string{isolationStatusActive, isolationStatusFailed} {
		if !valid[s] {
			t.Errorf("状态 %q 不在 model.HostIsolation 的状态机内", s)
		}
	}
}
