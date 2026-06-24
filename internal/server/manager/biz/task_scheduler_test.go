package biz

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupZombieDB 创建内存 SQLite 数据库，包含僵尸任务测试所需的表
func setupZombieDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	tables := []string{
		`CREATE TABLE scan_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			task_id        TEXT PRIMARY KEY,
			name           TEXT,
			type           TEXT DEFAULT 'baseline_scan',
			target_type    TEXT DEFAULT 'all',
			target_config  TEXT DEFAULT '{}',
			policy_id      TEXT,
			policy_ids     TEXT DEFAULT '[]',
			rule_ids       TEXT DEFAULT '[]',
			status         TEXT DEFAULT 'created',
			timeout_minutes INTEGER DEFAULT 10,
			dispatched_host_count INTEGER DEFAULT 0,
			completed_host_count  INTEGER DEFAULT 0,
			failed_reason  TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			executed_at    DATETIME,
			completed_at   DATETIME
		)`,
		`CREATE TABLE fix_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			task_id       TEXT PRIMARY KEY,
			host_ids      TEXT DEFAULT '[]',
			rule_ids      TEXT DEFAULT '[]',
			severities    TEXT DEFAULT '[]',
			status        TEXT DEFAULT 'pending',
			total_count   INTEGER DEFAULT 0,
			success_count INTEGER DEFAULT 0,
			failed_count  INTEGER DEFAULT 0,
			progress      INTEGER DEFAULT 0,
			created_by    TEXT,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at  DATETIME
		)`,
		`CREATE TABLE fim_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			task_id              TEXT PRIMARY KEY,
			policy_id            TEXT,
			status               TEXT DEFAULT 'pending',
			target_type          TEXT,
			target_config        TEXT DEFAULT '{}',
			dispatched_host_count INTEGER DEFAULT 0,
			completed_host_count  INTEGER DEFAULT 0,
			total_events         INTEGER DEFAULT 0,
			created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
			executed_at          DATETIME,
			completed_at         DATETIME
		)`,
		`CREATE TABLE antivirus_scan_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			name          TEXT,
			scan_type     TEXT DEFAULT 'quick',
			scan_paths    TEXT DEFAULT '[]',
			host_ids      TEXT DEFAULT '[]',
			status        TEXT DEFAULT 'pending',
			total_hosts   INTEGER DEFAULT 0,
			scanned_hosts INTEGER DEFAULT 0,
			threat_count  INTEGER DEFAULT 0,
			created_by    TEXT,
			started_at    DATETIME,
			finished_at   DATETIME,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("failed to create table: %v\nSQL: %s", err, ddl)
		}
	}
	return db
}

func newTestScheduler(db *gorm.DB) *TaskScheduler {
	return &TaskScheduler{
		db:     db,
		logger: zap.NewNop(),
	}
}

// --- 场景 1: 超时的 running 任务被标记为 failed ---

func TestTimeoutZombieTasks_ScanTask(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-3 * time.Hour) // 3 小时前（超过 2h 阈值）

	// 插入超时的 running 任务
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"scan-zombie-1", "running", oldTime)
	// 插入刚刚启动的 running 任务（不应被超时）
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"scan-fresh-1", "running", time.Now())
	// 插入已完成的任务（不应被影响）
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"scan-done-1", "completed", oldTime)

	s.timeoutZombieTasks()

	// 验证：超时的 running 任务被标记为 failed
	var zombie model.ScanTask
	db.Where("task_id = ?", "scan-zombie-1").First(&zombie)
	if zombie.Status != model.TaskStatusFailed {
		t.Errorf("zombie task should be failed, got %s", zombie.Status)
	}
	if zombie.FailedReason == "" {
		t.Error("zombie task should have failed_reason set")
	}
	if zombie.CompletedAt == nil {
		t.Error("zombie task should have completed_at set")
	}

	// 验证：刚启动的 running 任务未被影响
	var fresh model.ScanTask
	db.Where("task_id = ?", "scan-fresh-1").First(&fresh)
	if fresh.Status != model.TaskStatusRunning {
		t.Errorf("fresh running task should still be running, got %s", fresh.Status)
	}

	// 验证：已完成的任务未被影响
	var done model.ScanTask
	db.Where("task_id = ?", "scan-done-1").First(&done)
	if done.Status != model.TaskStatusCompleted {
		t.Errorf("completed task should still be completed, got %s", done.Status)
	}
}

func TestTimeoutZombieTasks_FixTask(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-3 * time.Hour)

	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fix-zombie-1", "running", oldTime)
	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fix-fresh-1", "running", time.Now())
	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fix-pending-1", "pending", oldTime)
	s.timeoutZombieTasks()

	var zombie model.FixTask
	db.Where("task_id = ?", "fix-zombie-1").First(&zombie)
	if zombie.Status != model.FixTaskStatusFailed {
		t.Errorf("zombie fix task should be failed, got %s", zombie.Status)
	}
	if zombie.CompletedAt == nil {
		t.Error("zombie fix task should have completed_at set")
	}

	var fresh model.FixTask
	db.Where("task_id = ?", "fix-fresh-1").First(&fresh)
	if fresh.Status != model.FixTaskStatusRunning {
		t.Errorf("fresh fix task should still be running, got %s", fresh.Status)
	}

	var pending model.FixTask
	db.Where("task_id = ?", "fix-pending-1").First(&pending)
	if pending.Status != model.FixTaskStatusPending {
		t.Errorf("pending fix task should still be pending, got %s", pending.Status)
	}
}

func TestTimeoutZombieTasks_FIMTask(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-3 * time.Hour)

	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fim-zombie-1", "running", oldTime)
	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fim-fresh-1", "running", time.Now())
	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"fim-completed-1", "completed", oldTime)

	s.timeoutZombieTasks()

	var zombie model.FIMTask
	db.Where("task_id = ?", "fim-zombie-1").First(&zombie)
	if zombie.Status != "failed" {
		t.Errorf("zombie FIM task should be failed, got %s", zombie.Status)
	}
	if zombie.CompletedAt == nil {
		t.Error("zombie FIM task should have completed_at set")
	}

	var fresh model.FIMTask
	db.Where("task_id = ?", "fim-fresh-1").First(&fresh)
	if fresh.Status != "running" {
		t.Errorf("fresh FIM task should still be running, got %s", fresh.Status)
	}

	var completed model.FIMTask
	db.Where("task_id = ?", "fim-completed-1").First(&completed)
	if completed.Status != "completed" {
		t.Errorf("completed FIM task should still be completed, got %s", completed.Status)
	}
}

func TestTimeoutZombieTasks_AntivirusScanTask(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-3 * time.Hour)

	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)",
		"av-zombie", "running", oldTime)
	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)",
		"av-fresh", "running", time.Now())
	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)",
		"av-cancelled", "cancelled", oldTime)

	s.timeoutZombieTasks()

	var zombie model.AntivirusScanTask
	db.Where("name = ?", "av-zombie").First(&zombie)
	if zombie.Status != "failed" {
		t.Errorf("zombie AV task should be failed, got %s", zombie.Status)
	}
	if zombie.FinishedAt == nil {
		t.Error("zombie AV task should have finished_at set")
	}

	var fresh model.AntivirusScanTask
	db.Where("name = ?", "av-fresh").First(&fresh)
	if fresh.Status != "running" {
		t.Errorf("fresh AV task should still be running, got %s", fresh.Status)
	}

	var cancelled model.AntivirusScanTask
	db.Where("name = ?", "av-cancelled").First(&cancelled)
	if cancelled.Status != "cancelled" {
		t.Errorf("cancelled AV task should still be cancelled, got %s", cancelled.Status)
	}
}

// --- 场景 2: 边界条件 ---

func TestTimeoutZombieTasks_ExactlyAtBoundary(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	// 恰好 2 小时前（刚好在边界上）
	boundary := time.Now().Add(-zombieTaskTimeout)

	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"scan-boundary", "running", boundary)

	s.timeoutZombieTasks()

	var task model.ScanTask
	db.Where("task_id = ?", "scan-boundary").First(&task)
	// 边界上的任务应该被超时（updated_at < cutoff，cutoff = now - 2h）
	// 由于 boundary 是在 timeoutZombieTasks 之前计算的，now 会比 boundary 晚一点
	// 所以 boundary < cutoff 成立，任务应被超时
	if task.Status != model.TaskStatusFailed {
		t.Errorf("boundary task should be failed, got %s", task.Status)
	}
}

func TestTimeoutZombieTasks_NilDB(t *testing.T) {
	s := &TaskScheduler{
		db:     nil,
		logger: zap.NewNop(),
	}
	// 不应 panic
	s.timeoutZombieTasks()
}

func TestTimeoutZombieTasks_NoRunningTasks(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	// 只有非 running 状态的任务
	db.Exec("INSERT INTO scan_tasks (task_id, status) VALUES (?, ?)", "scan-1", "completed")
	db.Exec("INSERT INTO scan_tasks (task_id, status) VALUES (?, ?)", "scan-2", "pending")
	db.Exec("INSERT INTO scan_tasks (task_id, status) VALUES (?, ?)", "scan-3", "failed")
	db.Exec("INSERT INTO scan_tasks (task_id, status) VALUES (?, ?)", "scan-4", "cancelled")

	s.timeoutZombieTasks()

	// 验证所有任务状态未变
	for _, id := range []string{"scan-1", "scan-2", "scan-3", "scan-4"} {
		var task model.ScanTask
		db.Where("task_id = ?", id).First(&task)
		switch id {
		case "scan-1":
			if task.Status != model.TaskStatusCompleted {
				t.Errorf("%s should be completed, got %s", id, task.Status)
			}
		case "scan-2":
			if task.Status != model.TaskStatusPending {
				t.Errorf("%s should be pending, got %s", id, task.Status)
			}
		case "scan-3":
			if task.Status != model.TaskStatusFailed {
				t.Errorf("%s should be failed, got %s", id, task.Status)
			}
		case "scan-4":
			if task.Status != model.TaskStatusCancelled {
				t.Errorf("%s should be cancelled, got %s", id, task.Status)
			}
		}
	}
}

// --- 场景 3: 多任务混合 ---

func TestTimeoutZombieTasks_MultipleZombiesAcrossTypes(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-4 * time.Hour)

	// 每种类型各插入 2 个 zombie + 1 个 fresh
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "s1", "running", oldTime)
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "s2", "running", oldTime)
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "s3", "running", time.Now())

	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "f1", "running", oldTime)
	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "f2", "running", oldTime)
	db.Exec("INSERT INTO fix_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "f3", "running", time.Now())

	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "fm1", "running", oldTime)
	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "fm2", "running", oldTime)
	db.Exec("INSERT INTO fim_tasks (task_id, status, updated_at) VALUES (?, ?, ?)", "fm3", "running", time.Now())

	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)", "av1", "running", oldTime)
	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)", "av2", "running", oldTime)
	db.Exec("INSERT INTO antivirus_scan_tasks (name, status, updated_at) VALUES (?, ?, ?)", "av3", "running", time.Now())

	s.timeoutZombieTasks()

	// 验证 zombie 被标记为 failed
	for _, id := range []string{"s1", "s2"} {
		var task model.ScanTask
		db.Where("task_id = ?", id).First(&task)
		if task.Status != model.TaskStatusFailed {
			t.Errorf("scan task %s should be failed, got %s", id, task.Status)
		}
	}
	for _, id := range []string{"f1", "f2"} {
		var task model.FixTask
		db.Where("task_id = ?", id).First(&task)
		if task.Status != model.FixTaskStatusFailed {
			t.Errorf("fix task %s should be failed, got %s", id, task.Status)
		}
	}
	for _, id := range []string{"fm1", "fm2"} {
		var task model.FIMTask
		db.Where("task_id = ?", id).First(&task)
		if task.Status != "failed" {
			t.Errorf("FIM task %s should be failed, got %s", id, task.Status)
		}
	}
	for _, name := range []string{"av1", "av2"} {
		var task model.AntivirusScanTask
		db.Where("name = ?", name).First(&task)
		if task.Status != "failed" {
			t.Errorf("AV task %s should be failed, got %s", name, task.Status)
		}
	}

	// 验证 fresh 任务未被影响
	var s3 model.ScanTask
	db.Where("task_id = ?", "s3").First(&s3)
	if s3.Status != model.TaskStatusRunning {
		t.Errorf("s3 should still be running, got %s", s3.Status)
	}
	var f3 model.FixTask
	db.Where("task_id = ?", "f3").First(&f3)
	if f3.Status != model.FixTaskStatusRunning {
		t.Errorf("f3 should still be running, got %s", f3.Status)
	}
	var fm3 model.FIMTask
	db.Where("task_id = ?", "fm3").First(&fm3)
	if fm3.Status != "running" {
		t.Errorf("fm3 should still be running, got %s", fm3.Status)
	}
	var av3 model.AntivirusScanTask
	db.Where("name = ?", "av3").First(&av3)
	if av3.Status != "running" {
		t.Errorf("av3 should still be running, got %s", av3.Status)
	}
}

// --- 场景 4: 幂等性 ---

func TestTimeoutZombieTasks_Idempotent(t *testing.T) {
	db := setupZombieDB(t)
	s := newTestScheduler(db)

	oldTime := time.Now().Add(-3 * time.Hour)
	db.Exec("INSERT INTO scan_tasks (task_id, status, updated_at) VALUES (?, ?, ?)",
		"scan-idem-1", "running", oldTime)

	// 执行两次
	s.timeoutZombieTasks()
	s.timeoutZombieTasks()

	var task model.ScanTask
	db.Where("task_id = ?", "scan-idem-1").First(&task)
	if task.Status != model.TaskStatusFailed {
		t.Errorf("task should be failed after idempotent calls, got %s", task.Status)
	}

	// 第二次执行不应 panic 或报错，且状态保持不变
	var count int64
	db.Model(&model.ScanTask{}).Where("task_id = ? AND status = ?", "scan-idem-1", model.TaskStatusFailed).Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 failed task, got %d", count)
	}
}
