package biz

import (
	"testing"
	"time"
)

func TestFIMDailyDue(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := func(day, hour, min int) time.Time { return time.Date(2026, 10, day, hour, min, 0, 0, loc) }
	ptr := func(v time.Time) *time.Time { return &v }
	day := 24 * time.Hour
	week := 7 * day

	cases := []struct {
		name       string
		now        time.Time
		hour       int
		interval   time.Duration
		lastFull   *time.Time
		due, missd bool
	}{
		{"还没到开始时刻", at(13, 3, 59), 4, day, ptr(at(12, 4, 0)), false, false},
		{"到点，上一轮是昨天", at(13, 4, 0), 4, day, ptr(at(12, 4, 2)), true, false},
		{"窗口内稍晚也起", at(13, 5, 55), 4, day, ptr(at(12, 4, 2)), true, false},
		{"今天已经起过", at(13, 4, 5), 4, day, ptr(at(13, 4, 0)), false, false},
		{"今天起过之后全天不再起", at(13, 23, 0), 4, day, ptr(at(13, 4, 0)), false, false},
		// 上一轮在昨天白天（旧调度留下的时刻）：今天到点照常起，不等满 24 小时。
		{"上一轮在昨天上午", at(13, 4, 0), 4, day, ptr(at(12, 11, 8)), true, false},
		// 上一轮在今天白天、早于今天的开始时刻不可能；晚于开始时刻的算今天已起过。
		{"上一轮在今天上午", at(12, 23, 30), 4, day, ptr(at(12, 11, 8)), false, false},
		{"错过窗口不在白天补", at(13, 6, 0), 4, day, ptr(at(12, 4, 0)), false, true},
		{"从未跑过，窗口内起", at(13, 4, 10), 4, day, nil, true, false},
		{"从未跑过，窗口外等明天", at(13, 15, 0), 4, day, nil, false, true},
		{"每周一轮，还没轮到", at(13, 4, 0), 4, week, ptr(at(10, 4, 0)), false, false},
		{"每周一轮，轮到了", at(13, 4, 0), 4, week, ptr(at(6, 4, 3)), true, false},
		{"开始时刻非法时按默认 4 点", at(13, 4, 0), 99, day, ptr(at(12, 4, 0)), true, false},
		{"开始时刻为 0 点", at(13, 0, 1), 0, day, ptr(at(12, 0, 1)), true, false},
	}
	for _, c := range cases {
		due, missed := fimDailyDue(c.now, c.hour, c.interval, c.lastFull)
		if due != c.due || missed != c.missd {
			t.Errorf("%s：得 due=%v missed=%v，期望 due=%v missed=%v", c.name, due, missed, c.due, c.missd)
		}
	}
}

// 手工对单台主机点的扫描不顶替当天的全量，也不改变它的时刻；到点后只起一轮。
//
// 原先按「距这条策略最近一次任务满 N 小时」调度，一次上午的单机任务就把此后每天的
// 全量扫描都带到了上午。
func TestScheduleFIMPeriodicTasks_FixedHour(t *testing.T) {
	db := setupZombieDB(t)
	if err := db.Exec(`CREATE TABLE fim_policies (
		tenant_id TEXT DEFAULT 't-default', policy_id TEXT PRIMARY KEY, name TEXT, description TEXT,
		watch_paths TEXT, exclude_paths TEXT, check_interval_hours INTEGER, check_start_hour INTEGER,
		target_type TEXT, target_config TEXT, escalation_timeout_min INTEGER, enabled INTEGER,
		created_at DATETIME, updated_at DATETIME)`).Error; err != nil {
		t.Fatalf("create fim_policies: %v", err)
	}
	if err := db.Exec(`INSERT INTO fim_policies (policy_id, name, watch_paths, check_interval_hours, check_start_hour, target_type, target_config, enabled)
		VALUES ('p1', 'general', '[]', 24, 4, 'all', '{}', 1)`).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	s := newTestScheduler(db)
	loc := time.Local
	at := func(day, hour, min int) time.Time { return time.Date(2026, 10, day, hour, min, 0, 0, loc) }
	addTask := func(id, targetType string, created time.Time) {
		t.Helper()
		if err := db.Exec(`INSERT INTO fim_tasks (task_id, policy_id, status, target_type, created_at) VALUES (?, 'p1', 'completed', ?, ?)`,
			id, targetType, created).Error; err != nil {
			t.Fatalf("seed task: %v", err)
		}
	}
	fullTasks := func() int64 {
		var n int64
		db.Table("fim_tasks").Where("policy_id = 'p1' AND target_type = 'all'").Count(&n)
		return n
	}

	addTask("full-12", "all", at(12, 4, 1))
	addTask("manual-single", "host_ids", at(12, 11, 4)) // 白天手工点的单机扫描

	// 距单机任务满 24 小时的时刻（次日上午）不该起全量。
	s.scheduleFIMPeriodicTasksAt(at(13, 3, 55))
	if got := fullTasks(); got != 1 {
		t.Fatalf("开始时刻之前不该起任务，全量任务数 = %d", got)
	}

	// 到点：起一轮，尽管距单机任务还不到 24 小时。
	s.scheduleFIMPeriodicTasksAt(at(13, 4, 0))
	if got := fullTasks(); got != 2 {
		t.Fatalf("到点应起一轮全量，全量任务数 = %d", got)
	}
	db.Exec(`UPDATE fim_tasks SET status = 'completed' WHERE status = 'pending'`)

	// 同一天后续的检查不再起，包括上午。
	for _, now := range []time.Time{at(13, 4, 5), at(13, 5, 30), at(13, 11, 10), at(13, 23, 55)} {
		s.scheduleFIMPeriodicTasksAt(now)
	}
	if got := fullTasks(); got != 2 {
		t.Fatalf("同一天只该起一轮，全量任务数 = %d", got)
	}

	// 第二天到点再起。
	s.scheduleFIMPeriodicTasksAt(at(14, 4, 3))
	if got := fullTasks(); got != 3 {
		t.Fatalf("第二天到点应再起一轮，全量任务数 = %d", got)
	}
}
