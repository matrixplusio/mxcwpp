package casework

import (
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func withResponseTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE response_actions (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		idempotency_key TEXT NOT NULL UNIQUE,
		action TEXT NOT NULL, target TEXT NOT NULL, incident_id TEXT,
		status TEXT NOT NULL DEFAULT 'pending', reason TEXT,
		requested_by TEXT NOT NULL, requested_at DATETIME,
		approved_by TEXT, approved_at DATETIME, reject_reason TEXT,
		executed_at DATETIME, result TEXT, error_msg TEXT,
		rolled_back_at DATETIME, rolled_back_by TEXT,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
}

// fakeExecutor 记录是否真的执行过。
type fakeExecutor struct {
	executed   int
	rolledBack int
	failWith   error
}

func (f *fakeExecutor) Execute(*model.ResponseAction) (string, error) {
	if f.failWith != nil {
		return "", f.failWith
	}
	f.executed++
	return "已隔离", nil
}
func (f *fakeExecutor) Rollback(*model.ResponseAction) error {
	f.rolledBack++
	return nil
}

func newRequest(key string) *model.ResponseAction {
	return &model.ResponseAction{
		IdempotencyKey: key,
		Action:         model.ResponseActionIsolateHost,
		Target:         "host-1",
		Reason:         "确认被植入 WebShell",
		RequestedBy:    "alice",
	}
}

func setup(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	s, db := newTestService(t)
	withResponseTable(t, db)
	return s, db
}

// TestExecute_RefusesWithoutApproval 未经审批的处置不得执行。
//
// 隔离主机会切断业务流量。原实现是一次 API 调用即刻生效，没有第二个人看过。
func TestExecute_RefusesWithoutApproval(t *testing.T) {
	s, _ := setup(t)
	act, err := s.RequestResponse(newRequest("k1"))
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{}
	if err := s.ExecuteResponse(act.ID, exec); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("未审批应拒绝执行，实际 %v", err)
	}
	if exec.executed != 0 {
		t.Error("未审批却已执行")
	}
}

// TestRequest_ForbidsSystemActors 系统身份不得发起处置申请。
//
// 硬禁自动处置不能只靠"目前没有自动路径"——那是碰巧成立。把系统身份挡在入口，
// 将来任何自动化想调用处置都会在这里失败，而不是悄悄执行成功。
func TestRequest_ForbidsSystemActors(t *testing.T) {
	s, _ := setup(t)
	for _, who := range []string{"system", "auto", "scheduler", "unknown", ""} {
		req := newRequest("k-" + who)
		req.RequestedBy = who
		if _, err := s.RequestResponse(req); !errors.Is(err, ErrAutoResponseForbidden) {
			t.Errorf("requested_by=%q 应被拒绝，实际 %v", who, err)
		}
	}
}

// TestApprove_RejectsSelfApproval 申请人不能审批自己的申请。
// 同一个人既提又批，审批就只是多点一次鼠标。
func TestApprove_RejectsSelfApproval(t *testing.T) {
	s, _ := setup(t)
	act, err := s.RequestResponse(newRequest("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveResponse(act.ID, "alice"); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("自审批应被拒绝，实际 %v", err)
	}
	if err := s.ApproveResponse(act.ID, "bob"); err != nil {
		t.Fatalf("他人审批应通过: %v", err)
	}
}

// TestRequest_IsIdempotent 同一幂等键只产生一次申请。
// 处置重复执行的后果不对称：多隔离一次可能切断本已恢复的业务。
func TestRequest_IsIdempotent(t *testing.T) {
	s, db := setup(t)
	first, err := s.RequestResponse(newRequest("same-key"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RequestResponse(newRequest("same-key"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Errorf("同一幂等键产生了两条申请: %d vs %d", first.ID, second.ID)
	}
	var n int64
	db.Model(&model.ResponseAction{}).Count(&n)
	if n != 1 {
		t.Errorf("申请数 = %d, want 1", n)
	}
}

// TestExecute_IsIdempotent 已执行的动作重复调用不再执行。
func TestExecute_IsIdempotent(t *testing.T) {
	s, _ := setup(t)
	act, _ := s.RequestResponse(newRequest("k1"))
	if err := s.ApproveResponse(act.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{}
	for i := 0; i < 3; i++ {
		if err := s.ExecuteResponse(act.ID, exec); err != nil {
			t.Fatalf("第 %d 次执行失败: %v", i+1, err)
		}
	}
	if exec.executed != 1 {
		t.Errorf("实际执行 %d 次，want 1", exec.executed)
	}
}

// TestExecute_FailureIsDistinguishable 执行失败要与"未执行"区分。
// 前者要人去查为什么没生效，后者只是还没轮到。
func TestExecute_FailureIsDistinguishable(t *testing.T) {
	s, db := setup(t)
	act, _ := s.RequestResponse(newRequest("k1"))
	if err := s.ApproveResponse(act.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{failWith: errors.New("agent 不在线")}
	if err := s.ExecuteResponse(act.ID, exec); err == nil {
		t.Fatal("执行失败应返回错误")
	}
	var got model.ResponseAction
	db.First(&got, act.ID)
	if got.Status != model.ResponseStatusFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if got.ErrorMsg == "" {
		t.Error("失败原因未记录")
	}
}

// TestRollback_OnlyAfterExecution 未执行的动作无从回滚。
func TestRollback_OnlyAfterExecution(t *testing.T) {
	s, db := setup(t)
	act, _ := s.RequestResponse(newRequest("k1"))
	exec := &fakeExecutor{}

	if err := s.RollbackResponse(act.ID, "bob", exec); !errors.Is(err, ErrNotExecuted) {
		t.Errorf("未执行不应可回滚，实际 %v", err)
	}
	if err := s.ApproveResponse(act.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.ExecuteResponse(act.ID, exec); err != nil {
		t.Fatal(err)
	}
	if err := s.RollbackResponse(act.ID, "bob", exec); err != nil {
		t.Fatalf("已执行应可回滚: %v", err)
	}
	if exec.rolledBack != 1 {
		t.Errorf("回滚执行 %d 次，want 1", exec.rolledBack)
	}
	var got model.ResponseAction
	db.First(&got, act.ID)
	if got.Status != model.ResponseStatusRolledBack {
		t.Errorf("status = %q, want rolled_back", got.Status)
	}
}

// TestResponse_WritesEvidenceToIncidentTimeline 处置全过程回流为事件证据。
//
// 复盘要能顺着一条时间线看完"发现→研判→申请→审批→执行"，而不是去另一个页面拼。
func TestResponse_WritesEvidenceToIncidentTimeline(t *testing.T) {
	s, db := setup(t)
	seedIncident(t, db, "inc-1", "critical")

	req := newRequest("k1")
	req.IncidentID = "inc-1"
	act, err := s.RequestResponse(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveResponse(act.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.ExecuteResponse(act.ID, &fakeExecutor{}); err != nil {
		t.Fatal(err)
	}

	events, err := s.Timeline("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("时间线应有 申请/审批/执行 三条，实际 %d 条", len(events))
	}
	for _, e := range events {
		if e.Type != model.IncidentEventEvidence {
			t.Errorf("处置记录应为证据类型，实际 %q", e.Type)
		}
		if e.Ref != "k1" {
			t.Errorf("证据应带幂等键以便追溯，实际 %q", e.Ref)
		}
	}
}

// TestReject_RequiresReason 驳回必须写明原因，否则申请人不知道该改什么。
func TestReject_RequiresReason(t *testing.T) {
	s, _ := setup(t)
	act, _ := s.RequestResponse(newRequest("k1"))
	if err := s.RejectResponse(act.ID, "bob", "  "); err == nil {
		t.Error("空原因驳回应被拒绝")
	}
	if err := s.RejectResponse(act.ID, "bob", "业务高峰，改走限流"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveResponse(act.ID, "bob"); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("已驳回的申请不应可再审批，实际 %v", err)
	}
}
