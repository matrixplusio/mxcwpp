package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	jobTickInterval = 30 * time.Second
	// jobSlotGrace 一个执行时刻之后多久内还可以起这一轮；过了就等下一个时刻。
	// 错过的不在别的时间补：把任务定在凌晨，就是不想让它出现在白天。
	jobSlotGrace = 2 * time.Hour
	// jobLongIntervalSlack 间隔超过一天时判断「上一轮够不够久」留的余量。
	jobLongIntervalSlack = 12 * time.Hour
	jobDefaultTimeout    = 2 * time.Hour
	jobErrorMaxLen       = 500
)

// PeriodicJob 一个可在控制台排期的后台任务。
type PeriodicJob struct {
	Key         string
	Name        string
	Description string
	// TouchesHosts 这个任务会向主机下发动作。只用于在控制台上提示，不影响调度。
	TouchesHosts bool

	DefaultIntervalHours int
	DefaultStartHour     int
	// FixedInterval 间隔不可改（例如日报只能一天一次）。
	FixedInterval bool
	// External 任务由别的组件自己执行，这里只保存它的排期供其读取，不调起、不提供立即执行。
	External bool

	Timeout time.Duration
	Run     func(ctx context.Context) error
}

// JobView 任务定义加上当前排期与最近一次执行情况。
type JobView struct {
	model.ScheduledJob
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	TouchesHosts  bool       `json:"touchesHosts"`
	FixedInterval bool       `json:"fixedInterval"`
	External      bool       `json:"external"`
	NextRunAt     *time.Time `json:"nextRunAt"`
}

// JobRunner 按 scheduled_jobs 表里的排期调起已登记的任务。
type JobRunner struct {
	db     *gorm.DB
	logger *zap.Logger
	now    func() time.Time

	mu      sync.Mutex
	jobs    map[string]*PeriodicJob
	running map[string]bool
	ctx     context.Context
}

// NewJobRunner 构造调度器。任务用 Register 登记，登记完再 Start。
func NewJobRunner(db *gorm.DB, logger *zap.Logger) *JobRunner {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &JobRunner{
		db: db, logger: logger, now: time.Now,
		jobs: make(map[string]*PeriodicJob), running: make(map[string]bool),
		ctx: context.Background(),
	}
}

var (
	defaultJobs   *JobRunner
	defaultJobsMu sync.RWMutex
)

// InitJobs 建立全局调度器。任务分散在 manager 启动流程的不同位置登记
// （有的依赖路由初始化时才构造出来的对象），所以用单例而不是层层传参。
func InitJobs(db *gorm.DB, logger *zap.Logger) *JobRunner {
	r := NewJobRunner(db, logger)
	defaultJobsMu.Lock()
	defaultJobs = r
	defaultJobsMu.Unlock()
	return r
}

// Jobs 返回全局调度器；未初始化时为 nil。
func Jobs() *JobRunner {
	defaultJobsMu.RLock()
	defer defaultJobsMu.RUnlock()
	return defaultJobs
}

// Register 登记一个任务。必须在 Start 之前调用；重复的 Key 或缺少执行体直接 panic——
// 这是接线错误，悄悄忽略的结果是那个任务从此不再执行，而且没有任何报错。
func (r *JobRunner) Register(j PeriodicJob) {
	if j.Key == "" || (!j.External && j.Run == nil) {
		panic(fmt.Sprintf("scheduler: 任务 %q 缺少 Key 或执行体", j.Key))
	}
	if !model.ValidScheduledJobInterval(j.DefaultIntervalHours) || j.DefaultStartHour < 0 || j.DefaultStartHour > 23 {
		panic(fmt.Sprintf("scheduler: 任务 %q 的默认排期不合法", j.Key))
	}
	if j.Timeout <= 0 {
		j.Timeout = jobDefaultTimeout
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.jobs[j.Key]; dup {
		panic(fmt.Sprintf("scheduler: 任务 %q 重复登记", j.Key))
	}
	r.jobs[j.Key] = &j
}

// Start 补齐排期记录并进入调度循环，直到 ctx 结束。
func (r *JobRunner) Start(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
	if err := r.ensureRows(); err != nil {
		r.logger.Error("定时任务排期初始化失败", zap.Error(err))
	}
	// 上次进程退出时还在执行的任务不会再有人回写结果。
	if err := r.db.Model(&model.ScheduledJob{}).Where("last_status = ?", model.JobStatusRunning).
		Update("last_status", model.JobStatusInterrupted).Error; err != nil {
		r.logger.Warn("重置中断的定时任务状态失败", zap.Error(err))
	}
	r.logger.Info("定时任务调度器已启动", zap.Int("jobs", len(r.jobs)))

	ticker := time.NewTicker(jobTickInterval)
	defer ticker.Stop()
	for {
		r.tick()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ensureRows 为还没有排期记录的任务写入默认排期；已有的不动。
func (r *JobRunner) ensureRows() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, j := range r.jobs {
		row := model.ScheduledJob{
			JobKey: j.Key, IntervalHours: j.DefaultIntervalHours, StartHour: j.DefaultStartHour,
			Enabled: true, UpdatedBy: "system", UpdatedAt: model.ToLocalTime(r.now()),
		}
		if err := r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *JobRunner) tick() {
	var rows []model.ScheduledJob
	if err := r.db.Find(&rows).Error; err != nil {
		r.logger.Warn("读取定时任务排期失败", zap.Error(err))
		return
	}
	now := r.now()
	for i := range rows {
		row := &rows[i]
		r.mu.Lock()
		job := r.jobs[row.JobKey]
		busy := r.running[row.JobKey]
		r.mu.Unlock()
		if job == nil || job.External || busy || !row.Enabled {
			continue
		}
		var last *time.Time
		if row.LastRunAt != nil {
			t := time.Time(*row.LastRunAt)
			last = &t
		}
		if !jobDue(now, row.StartHour, row.IntervalHours, last) {
			continue
		}
		r.launch(job, row.LastRunAt, model.JobTriggerSchedule)
	}
}

// jobDue 判断任务此刻该不该起新一轮。lastRun 为上一轮的开始时间，没有则为 nil。
//
// 从未执行过的任务同样等到执行时刻才起，不在登记后立刻跑：
// 否则一次发版会让所有新登记的任务同时执行一轮。
func jobDue(now time.Time, startHour, intervalHours int, lastRun *time.Time) bool {
	if !model.ValidScheduledJobInterval(intervalHours) || startHour < 0 || startHour > 23 {
		return false
	}
	slot := jobSlot(now, startHour, intervalHours)
	if lastRun != nil && !lastRun.Before(slot) {
		return false // 这个时刻的一轮已经起过
	}
	interval := time.Duration(intervalHours) * time.Hour
	if intervalHours > 24 && lastRun != nil && now.Sub(*lastRun) < interval-jobLongIntervalSlack {
		return false // 每隔几天一轮的任务，还没轮到今天
	}
	grace := jobSlotGrace
	if interval < grace {
		grace = interval
	}
	return now.Sub(slot) < grace
}

// jobSlot 返回不晚于 now 的最近一个执行时刻。
func jobSlot(now time.Time, startHour, intervalHours int) time.Time {
	step := intervalHours
	if step > 24 {
		step = 24
	}
	base := time.Date(now.Year(), now.Month(), now.Day(), startHour, 0, 0, 0, now.Location())
	// 把起点挪到不晚于 now，再按间隔往后找最后一个不晚于 now 的时刻。
	for base.After(now) {
		base = base.Add(-24 * time.Hour)
	}
	slot := base
	for next := slot.Add(time.Duration(step) * time.Hour); !next.After(now); next = slot.Add(time.Duration(step) * time.Hour) {
		slot = next
	}
	return slot
}

// jobNext 返回 now 之后的下一个执行时刻，仅供展示。
func jobNext(now time.Time, startHour, intervalHours int, lastRun *time.Time) time.Time {
	step := intervalHours
	if step > 24 {
		step = 24
	}
	next := jobSlot(now, startHour, intervalHours).Add(time.Duration(step) * time.Hour)
	if intervalHours > 24 && lastRun != nil {
		earliest := lastRun.Add(time.Duration(intervalHours)*time.Hour - jobLongIntervalSlack)
		for next.Before(earliest) {
			next = next.Add(24 * time.Hour)
		}
	}
	return next
}

// launch 认领并异步执行一轮。认领用「上次执行时间没变」作条件，
// 多个 manager 实例同时到点时只有一个能改成功。
func (r *JobRunner) launch(job *PeriodicJob, prevRun *model.LocalTime, trigger string) bool {
	r.mu.Lock()
	if r.running[job.Key] {
		r.mu.Unlock()
		return false
	}
	r.running[job.Key] = true
	ctx := r.ctx
	r.mu.Unlock()

	started := r.now()
	q := r.db.Model(&model.ScheduledJob{}).Where("job_key = ?", job.Key)
	if prevRun == nil {
		q = q.Where("last_run_at IS NULL")
	} else {
		q = q.Where("last_run_at = ?", *prevRun)
	}
	res := q.Updates(map[string]any{
		"last_run_at": model.ToLocalTime(started), "last_status": model.JobStatusRunning,
		"last_error": "", "last_trigger": trigger,
	})
	if res.Error != nil || res.RowsAffected == 0 {
		r.mu.Lock()
		delete(r.running, job.Key)
		r.mu.Unlock()
		if res.Error != nil {
			r.logger.Warn("认领定时任务失败", zap.String("job", job.Key), zap.Error(res.Error))
		}
		return false
	}

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.running, job.Key)
			r.mu.Unlock()
		}()
		runCtx, cancel := context.WithTimeout(ctx, job.Timeout)
		defer cancel()
		err := runJobSafely(runCtx, job)
		status, msg := model.JobStatusOK, ""
		if err != nil {
			status, msg = model.JobStatusFailed, truncateRunes(err.Error(), jobErrorMaxLen)
			r.logger.Error("定时任务执行失败", zap.String("job", job.Key), zap.Error(err))
		} else {
			r.logger.Info("定时任务执行完成", zap.String("job", job.Key),
				zap.String("trigger", trigger), zap.Duration("took", r.now().Sub(started)))
		}
		if e := r.db.Model(&model.ScheduledJob{}).Where("job_key = ?", job.Key).Updates(map[string]any{
			"last_status": status, "last_error": msg, "last_duration_ms": r.now().Sub(started).Milliseconds(),
		}).Error; e != nil {
			r.logger.Warn("回写定时任务结果失败", zap.String("job", job.Key), zap.Error(e))
		}
	}()
	return true
}

// runJobSafely 执行任务体，把 panic 变成一次失败：一个任务崩了不能带走整个 manager。
func runJobSafely(ctx context.Context, job *PeriodicJob) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("任务异常退出: %v", p)
		}
	}()
	return job.Run(ctx)
}

func truncateRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// 调用方可据此区分错误类型。
var (
	ErrJobNotFound = errors.New("任务不存在")
	ErrJobRunning  = errors.New("任务正在执行")
	ErrJobExternal = errors.New("该任务由其它组件执行，不支持立即执行")
)

// List 返回全部已登记任务的排期与最近一次执行情况。
func (r *JobRunner) List() ([]JobView, error) {
	var rows []model.ScheduledJob
	if err := r.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]JobView, 0, len(rows))
	for i := range rows {
		job := r.jobs[rows[i].JobKey]
		if job == nil {
			continue // 表里有、代码里已经没有的任务不展示
		}
		v := JobView{
			ScheduledJob: rows[i], Name: job.Name, Description: job.Description,
			TouchesHosts: job.TouchesHosts, FixedInterval: job.FixedInterval, External: job.External,
		}
		if r.running[job.Key] {
			v.LastStatus = model.JobStatusRunning
		}
		if rows[i].Enabled {
			var last *time.Time
			if rows[i].LastRunAt != nil {
				t := time.Time(*rows[i].LastRunAt)
				last = &t
			}
			next := jobNext(now, rows[i].StartHour, rows[i].IntervalHours, last)
			v.NextRunAt = &next
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartHour != out[j].StartHour {
			return out[i].StartHour < out[j].StartHour
		}
		return out[i].JobKey < out[j].JobKey
	})
	return out, nil
}

// JobSchedule 是一次排期修改。
type JobSchedule struct {
	IntervalHours int
	StartHour     int
	Enabled       bool
}

// Update 修改一个任务的排期。
func (r *JobRunner) Update(key string, s JobSchedule, actor string) error {
	r.mu.Lock()
	job := r.jobs[key]
	r.mu.Unlock()
	if job == nil {
		return ErrJobNotFound
	}
	if s.StartHour < 0 || s.StartHour > 23 {
		return errors.New("开始时刻必须在 0 到 23 之间")
	}
	if !model.ValidScheduledJobInterval(s.IntervalHours) {
		return errors.New("不支持的执行间隔")
	}
	if job.FixedInterval && s.IntervalHours != job.DefaultIntervalHours {
		return errors.New("该任务的执行间隔不可修改")
	}
	res := r.db.Model(&model.ScheduledJob{}).Where("job_key = ?", key).Updates(map[string]any{
		"interval_hours": s.IntervalHours, "start_hour": s.StartHour, "enabled": s.Enabled,
		"updated_by": actor, "updated_at": model.ToLocalTime(r.now()),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrJobNotFound
	}
	r.logger.Warn("定时任务排期已修改", zap.String("job", key), zap.Int("interval_hours", s.IntervalHours),
		zap.Int("start_hour", s.StartHour), zap.Bool("enabled", s.Enabled), zap.String("actor", actor))
	return nil
}

// RunNow 立即执行一轮，不等到点。停用的任务也可以手工执行。
func (r *JobRunner) RunNow(key, actor string) error {
	r.mu.Lock()
	job := r.jobs[key]
	r.mu.Unlock()
	if job == nil {
		return ErrJobNotFound
	}
	if job.External {
		return ErrJobExternal
	}
	var row model.ScheduledJob
	if err := r.db.Where("job_key = ?", key).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrJobNotFound
		}
		return err
	}
	if !r.launch(job, row.LastRunAt, model.JobTriggerManual) {
		return ErrJobRunning
	}
	r.logger.Warn("定时任务被手工触发", zap.String("job", key), zap.String("actor", actor))
	return nil
}
