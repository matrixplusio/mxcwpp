package biz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/audit"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 默认情报同步计划：每天 03:00 拉取一次 IOC Feed（新部署即自动同步，无需手动触发）
const (
	defaultIntelScheduleName = "默认情报同步"
	defaultIntelCronExpr     = "0 0 3 * * *" // 6 段：秒 分 时 日 月 周
)

// IntelSyncScheduler 威胁情报同步定时调度器
type IntelSyncScheduler struct {
	db          *gorm.DB
	logger      *zap.Logger
	threatIntel *ThreatIntel
	cron        *cron.Cron
	entryMap    map[uint]cron.EntryID // schedule ID → cron entry ID
	mu          sync.Mutex
}

// NewIntelSyncScheduler 创建情报同步调度器
func NewIntelSyncScheduler(db *gorm.DB, logger *zap.Logger, threatIntel *ThreatIntel) *IntelSyncScheduler {
	return &IntelSyncScheduler{
		db:          db,
		logger:      logger,
		threatIntel: threatIntel,
		cron:        cron.New(cron.WithSeconds()),
		entryMap:    make(map[uint]cron.EntryID),
	}
}

// Start 启动调度器：无计划时种入默认计划，再加载所有启用计划
func (s *IntelSyncScheduler) Start() error {
	s.logger.Info("启动威胁情报同步调度器")

	if err := s.seedDefault(); err != nil {
		s.logger.Warn("种入默认情报同步计划失败", zap.Error(err))
	}

	var schedules []model.IntelSyncSchedule
	if err := s.db.Where("enabled = ?", true).Find(&schedules).Error; err != nil {
		return fmt.Errorf("加载情报同步计划失败: %w", err)
	}

	s.mu.Lock()
	for _, sch := range schedules {
		if err := s.addCronJob(sch); err != nil {
			s.logger.Warn("加载情报同步计划失败", zap.Uint("id", sch.ID), zap.String("name", sch.Name), zap.Error(err))
		}
	}
	s.mu.Unlock()

	s.cron.Start()
	s.logger.Info("威胁情报同步调度器已启动", zap.Int("active_jobs", len(s.entryMap)))
	return nil
}

// seedDefault 若无任何同步计划，自动建一个默认日同步计划
func (s *IntelSyncScheduler) seedDefault() error {
	var count int64
	if err := s.db.Model(&model.IntelSyncSchedule{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(defaultIntelCronExpr)
	if err != nil {
		return err
	}
	next := model.ToLocalTime(schedule.Next(time.Now()))
	def := &model.IntelSyncSchedule{
		Name:      defaultIntelScheduleName,
		CronExpr:  defaultIntelCronExpr,
		Enabled:   true,
		NextRunAt: &next,
		CreatedBy: "system",
	}
	if err := s.db.Create(def).Error; err != nil {
		return err
	}
	s.logger.Info("已种入默认情报同步计划", zap.String("cron", defaultIntelCronExpr))
	return nil
}

// Stop 优雅停止调度器
func (s *IntelSyncScheduler) Stop() {
	s.logger.Info("停止威胁情报同步调度器")
	ctx := s.cron.Stop()
	<-ctx.Done()
}

// AddSchedule 创建同步计划
func (s *IntelSyncScheduler) AddSchedule(sch *model.IntelSyncSchedule) error {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(sch.CronExpr)
	if err != nil {
		return fmt.Errorf("无效的 Cron 表达式: %w", err)
	}

	nextRun := schedule.Next(time.Now())
	lt := model.ToLocalTime(nextRun)
	sch.NextRunAt = &lt

	if err := s.db.Create(sch).Error; err != nil {
		return fmt.Errorf("创建情报同步计划失败: %w", err)
	}

	if sch.Enabled {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.addCronJob(*sch)
	}
	return nil
}

// RemoveSchedule 删除同步计划
func (s *IntelSyncScheduler) RemoveSchedule(id uint) error {
	s.mu.Lock()
	if entryID, ok := s.entryMap[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entryMap, id)
	}
	s.mu.Unlock()

	return s.db.Delete(&model.IntelSyncSchedule{}, id).Error
}

// UpdateSchedule 更新同步计划
func (s *IntelSyncScheduler) UpdateSchedule(id uint, updates map[string]any) error {
	if err := s.db.Model(&model.IntelSyncSchedule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}

	var sch model.IntelSyncSchedule
	if err := s.db.First(&sch, id).Error; err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if entryID, ok := s.entryMap[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entryMap, id)
	}

	if sch.Enabled {
		return s.addCronJob(sch)
	}
	return nil
}

// ToggleSchedule 启用/禁用同步计划
func (s *IntelSyncScheduler) ToggleSchedule(id uint) error {
	var sch model.IntelSyncSchedule
	if err := s.db.First(&sch, id).Error; err != nil {
		return err
	}

	sch.Enabled = !sch.Enabled
	if err := s.db.Save(&sch).Error; err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if sch.Enabled {
		return s.addCronJob(sch)
	}

	if entryID, ok := s.entryMap[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entryMap, id)
	}
	return nil
}

// RunNow 立即触发一次同步（异步执行）
func (s *IntelSyncScheduler) RunNow(id uint) error {
	var sch model.IntelSyncSchedule
	if err := s.db.First(&sch, id).Error; err != nil {
		return err
	}
	go s.executeSchedule(sch.ID)
	return nil
}

// addCronJob 注册 cron 任务（调用方须持有 s.mu 或确保无竞争）
func (s *IntelSyncScheduler) addCronJob(sch model.IntelSyncSchedule) error {
	scheduleID := sch.ID
	entryID, err := s.cron.AddFunc(sch.CronExpr, func() {
		s.executeSchedule(scheduleID)
	})
	if err != nil {
		return fmt.Errorf("注册 cron 任务失败: %w", err)
	}

	s.entryMap[scheduleID] = entryID
	s.logger.Info("注册情报同步计划",
		zap.Uint("id", sch.ID),
		zap.String("name", sch.Name),
		zap.String("cron", sch.CronExpr))
	return nil
}

// executeSchedule 执行同步计划
func (s *IntelSyncScheduler) executeSchedule(scheduleID uint) {
	s.logger.Info("定时情报同步触发", zap.Uint("schedule_id", scheduleID))

	now := model.Now()
	s.db.Model(&model.IntelSyncSchedule{}).Where("id = ?", scheduleID).
		Update("last_run_at", now)

	exec := model.IntelSyncExecution{
		ScheduleID: scheduleID,
		Status:     "running",
		StartedAt:  now,
	}
	s.db.Create(&exec)

	err := s.threatIntel.SyncIOCs(context.Background())

	finishedAt := model.Now()
	duration := int(time.Since(time.Time(now)).Seconds())
	updates := map[string]any{
		"finished_at": finishedAt,
		"duration":    duration,
	}
	outcome := model.OutcomeSuccess
	if err != nil {
		updates["status"] = "failed"
		updates["error_msg"] = err.Error()
		outcome = model.OutcomeFailure
		s.logger.Error("定时情报同步执行失败", zap.Uint("schedule_id", scheduleID), zap.Error(err))
	} else {
		updates["status"] = "success"
		// 回填本次同步后的 IOC 总数（取最新快照）
		var snap model.IOCSnapshot
		if e := s.db.Order("id DESC").First(&snap).Error; e == nil {
			updates["ioc_count"] = snap.Count
		}
	}
	s.db.Model(&exec).Updates(updates)

	detail := fmt.Sprintf("duration=%ds", duration)
	if err != nil {
		detail += " error=" + err.Error()
	}
	audit.Record(context.Background(), audit.Event{
		ActorType:    model.ActorTypeSystem,
		Username:     "intel-sync-scheduler",
		Action:       "threat_intel.sync",
		Outcome:      outcome,
		ResourceType: "intel_sync_schedule",
		ResourceID:   fmt.Sprintf("%d", scheduleID),
		Detail:       detail,
	})

	s.mu.Lock()
	entry, ok := s.entryMap[scheduleID]
	s.mu.Unlock()
	if ok {
		nextRun := s.cron.Entry(entry).Next
		lt := model.ToLocalTime(nextRun)
		s.db.Model(&model.IntelSyncSchedule{}).Where("id = ?", scheduleID).
			Update("next_run_at", lt)
	}
}
