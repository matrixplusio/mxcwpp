package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestJobDue(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := func(day, hour, min int) time.Time { return time.Date(2026, 10, day, hour, min, 0, 0, loc) }
	ptr := func(v time.Time) *time.Time { return &v }

	cases := []struct {
		name     string
		now      time.Time
		start    int
		interval int
		last     *time.Time
		want     bool
	}{
		{"每天一轮：没到点", at(13, 4, 59), 5, 24, ptr(at(12, 5, 0)), false},
		{"每天一轮：到点", at(13, 5, 0), 5, 24, ptr(at(12, 5, 0)), true},
		{"每天一轮：今天已起过", at(13, 5, 1), 5, 24, ptr(at(13, 5, 0)), false},
		{"每天一轮：错过窗口不补", at(13, 7, 0), 5, 24, ptr(at(12, 5, 0)), false},
		// 从未执行过也要等到点：否则一次发版会让所有新登记的任务同时跑一轮。
		{"从未执行：不在登记后立刻跑", at(13, 11, 0), 5, 24, nil, false},
		{"从未执行：到点才跑", at(13, 5, 10), 5, 24, nil, true},
		{"每 6 小时从 1 点起：07:00 到点", at(13, 7, 0), 1, 6, ptr(at(13, 1, 0)), true},
		{"每 6 小时从 1 点起：07:00 这轮已起", at(13, 8, 30), 1, 6, ptr(at(13, 7, 0)), false},
		{"每 6 小时从 1 点起：凌晨 00:30 属于昨天 19:00 那一格，已过窗口", at(13, 0, 30), 1, 6, ptr(at(12, 13, 0)), false},
		{"每 4 小时从 0 点起：跨日的 00:00", at(13, 0, 1), 0, 4, ptr(at(12, 20, 0)), true},
		{"每小时：窗口不超过间隔", at(13, 9, 59), 0, 1, ptr(at(13, 8, 0)), true},
		{"手工在白天跑过不影响下一个时刻", at(13, 5, 0), 5, 24, ptr(at(12, 15, 0)), true},
		{"每周一轮：还没轮到", at(13, 3, 0), 3, 168, ptr(at(10, 3, 0)), false},
		{"每周一轮：轮到了", at(13, 3, 0), 3, 168, ptr(at(6, 3, 2)), true},
		{"非法间隔不执行", at(13, 5, 0), 5, 5, nil, false},
		{"非法时刻不执行", at(13, 5, 0), 24, 24, nil, false},
	}
	for _, c := range cases {
		if got := jobDue(c.now, c.start, c.interval, c.last); got != c.want {
			t.Errorf("%s：得 %v，期望 %v", c.name, got, c.want)
		}
	}
}

func TestJobNext(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := func(day, hour, min int) time.Time { return time.Date(2026, 10, day, hour, min, 0, 0, loc) }
	if got := jobNext(at(13, 11, 0), 5, 24, nil); !got.Equal(at(14, 5, 0)) {
		t.Errorf("每天 5 点，11 点时的下一次应是明天 5 点，得 %v", got)
	}
	if got := jobNext(at(13, 2, 0), 1, 6, nil); !got.Equal(at(13, 7, 0)) {
		t.Errorf("每 6 小时从 1 点起，2 点时的下一次应是 7 点，得 %v", got)
	}
	last := at(12, 3, 0)
	if got := jobNext(at(13, 9, 0), 3, 168, &last); !got.Equal(at(19, 3, 0)) {
		t.Errorf("每周一轮，上次 12 日 3 点，下一次应是 19 日 3 点，得 %v", got)
	}
}

func newJobTestRunner(t *testing.T) *JobRunner {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.ScheduledJob{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewJobRunner(db, zap.NewNop())
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时：%s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func jobRow(t *testing.T, r *JobRunner, key string) model.ScheduledJob {
	t.Helper()
	var row model.ScheduledJob
	if err := r.db.Where("job_key = ?", key).First(&row).Error; err != nil {
		t.Fatalf("load %s: %v", key, err)
	}
	return row
}

// 到点只起一轮；进程重启（新建一个调度器、共用同一张表）后不会重新计时再跑一遍。
func TestJobRunnerRunsOncePerSlotAcrossRestart(t *testing.T) {
	r := newJobTestRunner(t)
	var runs atomic.Int32
	job := PeriodicJob{Key: "j", Name: "j", DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error { runs.Add(1); return nil }}
	r.Register(job)
	if err := r.ensureRows(); err != nil {
		t.Fatalf("ensure rows: %v", err)
	}
	clock := time.Date(2026, 10, 13, 4, 59, 0, 0, time.Local)
	r.now = func() time.Time { return clock }

	r.tick()
	time.Sleep(20 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("没到点就执行了")
	}

	clock = time.Date(2026, 10, 13, 5, 0, 30, 0, time.Local)
	r.tick()
	waitFor(t, "到点执行", func() bool { return jobRow(t, r, "j").LastStatus == model.JobStatusOK })
	r.tick()
	time.Sleep(20 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("同一时刻应只执行一轮，执行了 %d 轮", runs.Load())
	}
	if row := jobRow(t, r, "j"); row.LastTrigger != model.JobTriggerSchedule || row.LastRunAt == nil {
		t.Fatalf("执行记录不完整：%+v", row)
	}

	// 「重启」：新调度器接手同一张表，时间还在同一个窗口里。
	r2 := NewJobRunner(r.db, zap.NewNop())
	r2.Register(job)
	if err := r2.ensureRows(); err != nil {
		t.Fatalf("ensure rows: %v", err)
	}
	clock2 := time.Date(2026, 10, 13, 5, 30, 0, 0, time.Local)
	r2.now = func() time.Time { return clock2 }
	r2.tick()
	time.Sleep(20 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("重启后不该重跑，执行了 %d 轮", runs.Load())
	}

	// 第二天到点再起。
	clock2 = time.Date(2026, 10, 14, 5, 0, 10, 0, time.Local)
	r2.tick()
	waitFor(t, "第二天执行", func() bool { return runs.Load() == 2 })
}

// 停用的任务到点不执行；失败与 panic 都记成失败而不是带走进程。
func TestJobRunnerDisabledAndFailures(t *testing.T) {
	r := newJobTestRunner(t)
	var ran atomic.Int32
	r.Register(PeriodicJob{Key: "off", Name: "off", DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error { ran.Add(1); return nil }})
	r.Register(PeriodicJob{Key: "fail", Name: "fail", DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error { return errors.New("上游不可达") }})
	r.Register(PeriodicJob{Key: "boom", Name: "boom", DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error { panic("nil map") }})
	if err := r.ensureRows(); err != nil {
		t.Fatalf("ensure rows: %v", err)
	}
	if err := r.Update("off", JobSchedule{IntervalHours: 24, StartHour: 5, Enabled: false}, "alice"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	clock := time.Date(2026, 10, 13, 5, 1, 0, 0, time.Local)
	r.now = func() time.Time { return clock }
	r.tick()

	waitFor(t, "失败任务回写", func() bool { return jobRow(t, r, "fail").LastStatus == model.JobStatusFailed })
	waitFor(t, "panic 任务回写", func() bool { return jobRow(t, r, "boom").LastStatus == model.JobStatusFailed })
	if got := jobRow(t, r, "fail").LastError; got != "上游不可达" {
		t.Errorf("失败原因 = %q", got)
	}
	if ran.Load() != 0 || jobRow(t, r, "off").LastRunAt != nil {
		t.Error("停用的任务不该执行")
	}

	// 停用的任务仍可手工执行。
	if err := r.RunNow("off", "alice"); err != nil {
		t.Fatalf("run now: %v", err)
	}
	waitFor(t, "手工执行", func() bool { return ran.Load() == 1 })
	waitFor(t, "手工执行回写", func() bool { return jobRow(t, r, "off").LastStatus == model.JobStatusOK })
	if row := jobRow(t, r, "off"); row.LastTrigger != model.JobTriggerManual {
		t.Errorf("触发方式 = %q，期望 manual", row.LastTrigger)
	}
}

func TestJobRunnerUpdateAndRunNowGuards(t *testing.T) {
	r := newJobTestRunner(t)
	release := make(chan struct{})
	r.Register(PeriodicJob{Key: "slow", Name: "slow", DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error { <-release; return nil }})
	r.Register(PeriodicJob{Key: "digest", Name: "digest", DefaultIntervalHours: 24, DefaultStartHour: 9,
		FixedInterval: true, External: true})
	if err := r.ensureRows(); err != nil {
		t.Fatalf("ensure rows: %v", err)
	}

	bad := []JobSchedule{
		{IntervalHours: 24, StartHour: 24, Enabled: true},
		{IntervalHours: 24, StartHour: -1, Enabled: true},
		{IntervalHours: 5, StartHour: 3, Enabled: true},
		{IntervalHours: 0, StartHour: 3, Enabled: true},
	}
	for _, s := range bad {
		if err := r.Update("slow", s, "alice"); err == nil {
			t.Errorf("排期 %+v 应被拒绝", s)
		}
	}
	if err := r.Update("nope", JobSchedule{IntervalHours: 24, StartHour: 3, Enabled: true}, "alice"); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("不存在的任务应回 ErrJobNotFound，得 %v", err)
	}
	if err := r.Update("digest", JobSchedule{IntervalHours: 12, StartHour: 9, Enabled: true}, "alice"); err == nil {
		t.Error("间隔固定的任务不该能改间隔")
	}
	if err := r.Update("digest", JobSchedule{IntervalHours: 24, StartHour: 8, Enabled: true}, "alice"); err != nil {
		t.Errorf("改开始时刻应成功：%v", err)
	}
	if row := jobRow(t, r, "digest"); row.StartHour != 8 || row.UpdatedBy != "alice" {
		t.Errorf("修改未落库：%+v", row)
	}
	if err := r.RunNow("digest", "alice"); !errors.Is(err, ErrJobExternal) {
		t.Errorf("外部任务不支持立即执行，得 %v", err)
	}

	if err := r.RunNow("slow", "alice"); err != nil {
		t.Fatalf("run now: %v", err)
	}
	if err := r.RunNow("slow", "alice"); !errors.Is(err, ErrJobRunning) {
		t.Errorf("执行中再触发应回 ErrJobRunning，得 %v", err)
	}
	close(release)
	waitFor(t, "慢任务结束", func() bool { return jobRow(t, r, "slow").LastStatus == model.JobStatusOK })

	items, err := r.List()
	if err != nil || len(items) != 2 {
		t.Fatalf("list：%d 项 err=%v", len(items), err)
	}
}

// 内置任务都登记得上，且每一个都有执行体或被标为外部执行。
// 漏接一个的后果是那个任务从此不再执行，而且没有任何报错。
func TestRegisterBuiltinJobs(t *testing.T) {
	r := newJobTestRunner(t)
	RegisterBuiltinJobs(r, r.db, zap.NewNop())
	want := []string{JobVulnFPCleanup, JobMySQLRetention, JobBaselineMaint, JobAutoTuning, JobCriticalAdmission, model.JobKeyAlertDigest}
	for _, k := range want {
		j := r.jobs[k]
		if j == nil {
			t.Errorf("任务 %s 未登记", k)
			continue
		}
		if !j.External && j.Run == nil {
			t.Errorf("任务 %s 没有执行体", k)
		}
		if j.Name == "" || j.Description == "" {
			t.Errorf("任务 %s 缺少名称或说明", k)
		}
	}
	if len(r.jobs) != len(want) {
		t.Errorf("登记了 %d 个任务，期望 %d 个：新增任务要同步更新这里", len(r.jobs), len(want))
	}
}
