package scheduler

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupTaskTimeoutTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	// 手动建表，避开 MySQL 特有语法
	db.Exec(`CREATE TABLE scan_tasks (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		task_id TEXT PRIMARY KEY,
		name TEXT,
		type TEXT,
		target_type TEXT,
		target_config TEXT,
		policy_id TEXT,
		policy_ids TEXT,
		rule_ids TEXT,
		status TEXT DEFAULT 'created',
		timeout_minutes INTEGER DEFAULT 10,
		retry_count INTEGER DEFAULT 0,
		max_retries INTEGER DEFAULT 2,
		dispatched_host_count INTEGER DEFAULT 0,
		completed_host_count INTEGER DEFAULT 0,
		failed_reason TEXT DEFAULT '',
		created_at TIMESTAMP,
		updated_at TIMESTAMP,
		executed_at TIMESTAMP,
		completed_at TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT,
		host_id TEXT,
		rule_id TEXT
	)`)
	db.Exec(`CREATE TABLE task_host_status (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT,
		host_id TEXT,
		status TEXT DEFAULT 'dispatched',
		error_message TEXT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)
	return db
}

// seedResults 为任务插入 n 条结果，使 resultCount>0
func seedResults(db *gorm.DB, taskID string, n int) {
	for i := range n {
		db.Exec(`INSERT INTO scan_results (task_id, host_id, rule_id) VALUES (?, ?, ?)`,
			taskID, "h", i)
	}
}

func fetchStatus(t *testing.T, db *gorm.DB, taskID string) (status string, retry int) {
	t.Helper()
	var tk model.ScanTask
	if err := db.Where("task_id = ?", taskID).First(&tk).Error; err != nil {
		t.Fatalf("fetch task: %v", err)
	}
	return string(tk.Status), tk.RetryCount
}

func TestHandleRunningTaskTimeout(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		task           model.ScanTask
		resultCount    int
		wantStatus     model.TaskStatus
		wantRetryCount int
	}{
		{
			name: "全部主机已返回结果_完成",
			task: model.ScanTask{TaskID: "t-all-done", Status: model.TaskStatusRunning,
				DispatchedHostCount: 5, CompletedHostCount: 5, RetryCount: 0, MaxRetries: 2},
			resultCount: 50, wantStatus: model.TaskStatusCompleted, wantRetryCount: 0,
		},
		{
			name: "部分未完成_重试未耗尽_回pending重排",
			task: model.ScanTask{TaskID: "t-retry", Status: model.TaskStatusRunning,
				DispatchedHostCount: 5, CompletedHostCount: 3, RetryCount: 0, MaxRetries: 2},
			resultCount: 30, wantStatus: model.TaskStatusPending, wantRetryCount: 1,
		},
		{
			name: "部分未完成_重试耗尽_有结果_partial",
			task: model.ScanTask{TaskID: "t-partial", Status: model.TaskStatusRunning,
				DispatchedHostCount: 5, CompletedHostCount: 3, RetryCount: 2, MaxRetries: 2},
			resultCount: 30, wantStatus: model.TaskStatusPartial, wantRetryCount: 2,
		},
		{
			name: "无任何结果_重试耗尽_failed",
			task: model.ScanTask{TaskID: "t-failed", Status: model.TaskStatusRunning,
				DispatchedHostCount: 5, CompletedHostCount: 0, RetryCount: 2, MaxRetries: 2},
			resultCount: 0, wantStatus: model.TaskStatusFailed, wantRetryCount: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTaskTimeoutTestDB(t)
			if err := db.Create(&tc.task).Error; err != nil {
				t.Fatalf("seed task: %v", err)
			}
			seedResults(db, tc.task.TaskID, tc.resultCount)

			handleRunningTaskTimeout(db, logger, &tc.task)

			gotStatus, gotRetry := fetchStatus(t, db, tc.task.TaskID)
			if gotStatus != string(tc.wantStatus) {
				t.Errorf("status = %q, want %q", gotStatus, tc.wantStatus)
			}
			if gotRetry != tc.wantRetryCount {
				t.Errorf("retry_count = %d, want %d", gotRetry, tc.wantRetryCount)
			}
		})
	}
}

// TestHandleRunningTaskTimeout_RetryThenExhaust 验证连续超时直至重试耗尽转 partial
func TestHandleRunningTaskTimeout_RetryThenExhaust(t *testing.T) {
	logger := zap.NewNop()
	db := setupTaskTimeoutTestDB(t)

	task := model.ScanTask{TaskID: "t-seq", Status: model.TaskStatusRunning,
		DispatchedHostCount: 10, CompletedHostCount: 6, RetryCount: 0, MaxRetries: 2}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	seedResults(db, task.TaskID, 60)

	// 第 1 次超时 → pending, retry=1
	handleRunningTaskTimeout(db, logger, &task)
	if s, r := fetchStatus(t, db, task.TaskID); s != string(model.TaskStatusPending) || r != 1 {
		t.Fatalf("round1: status=%s retry=%d, want pending/1", s, r)
	}

	// 模拟重排后仍未补齐，再次进入 running 超时（retry=1<2）→ pending, retry=2
	task.Status = model.TaskStatusRunning
	task.RetryCount = 1
	handleRunningTaskTimeout(db, logger, &task)
	if s, r := fetchStatus(t, db, task.TaskID); s != string(model.TaskStatusPending) || r != 2 {
		t.Fatalf("round2: status=%s retry=%d, want pending/2", s, r)
	}

	// retry 耗尽（2==2）→ partial
	task.Status = model.TaskStatusRunning
	task.RetryCount = 2
	handleRunningTaskTimeout(db, logger, &task)
	if s, _ := fetchStatus(t, db, task.TaskID); s != string(model.TaskStatusPartial) {
		t.Fatalf("round3: status=%s, want partial", s)
	}
}
