package biz

import (
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ScanScheduler 漏洞扫描定时调度器
type ScanScheduler struct {
	db       *gorm.DB
	logger   *zap.Logger
	scanner  *VulnScanner
	cron     *cron.Cron
	entryMap map[uint]cron.EntryID // schedule ID → cron entry ID
	mu       sync.Mutex
}

// NewScanScheduler 创建调度器
func NewScanScheduler(db *gorm.DB, logger *zap.Logger, scanner *VulnScanner) *ScanScheduler {
	return &ScanScheduler{
		db:       db,
		logger:   logger,
		scanner:  scanner,
		cron:     cron.New(cron.WithSeconds()),
		entryMap: make(map[uint]cron.EntryID),
	}
}

// Start 启动调度器，加载所有启用的扫描计划
func (s *ScanScheduler) Start() error {
	s.logger.Info("启动漏洞扫描调度器")

	var schedules []model.ScanSchedule
	if err := s.db.Where("enabled = ?", true).Find(&schedules).Error; err != nil {
		return fmt.Errorf("加载扫描计划失败: %w", err)
	}

	s.mu.Lock()
	for _, sch := range schedules {
		if err := s.addCronJob(sch); err != nil {
			s.logger.Warn("加载扫描计划失败", zap.Uint("id", sch.ID), zap.String("name", sch.Name), zap.Error(err))
		}
	}
	s.mu.Unlock()

	s.cron.Start()
	s.logger.Info("漏洞扫描调度器已启动", zap.Int("active_jobs", len(s.entryMap)))
	return nil
}

// Stop 优雅停止调度器
func (s *ScanScheduler) Stop() {
	s.logger.Info("停止漏洞扫描调度器")
	ctx := s.cron.Stop()
	<-ctx.Done()
}

// AddSchedule 创建扫描计划
func (s *ScanScheduler) AddSchedule(sch *model.ScanSchedule) error {
	// 验证 Cron 表达式
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(sch.CronExpr)
	if err != nil {
		return fmt.Errorf("无效的 Cron 表达式: %w", err)
	}

	// 计算下次执行时间
	nextRun := schedule.Next(time.Now())
	lt := model.ToLocalTime(nextRun)
	sch.NextRunAt = &lt

	if err := s.db.Create(sch).Error; err != nil {
		return fmt.Errorf("创建扫描计划失败: %w", err)
	}

	if sch.Enabled {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.addCronJob(*sch)
	}
	return nil
}

// RemoveSchedule 删除扫描计划
func (s *ScanScheduler) RemoveSchedule(id uint) error {
	s.mu.Lock()
	if entryID, ok := s.entryMap[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entryMap, id)
	}
	s.mu.Unlock()

	return s.db.Delete(&model.ScanSchedule{}, id).Error
}

// UpdateSchedule 更新扫描计划
func (s *ScanScheduler) UpdateSchedule(id uint, updates map[string]any) error {
	if err := s.db.Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}

	// 重新加载
	var sch model.ScanSchedule
	if err := s.db.First(&sch, id).Error; err != nil {
		return err
	}

	// 移除旧 job + 添加新 job
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

// ToggleSchedule 启用/禁用扫描计划
func (s *ScanScheduler) ToggleSchedule(id uint) error {
	var sch model.ScanSchedule
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

// addCronJob 注册 cron 任务（调用方须持有 s.mu 或确保无竞争）
func (s *ScanScheduler) addCronJob(sch model.ScanSchedule) error {
	scheduleID := sch.ID
	scanType := sch.ScanType

	entryID, err := s.cron.AddFunc(sch.CronExpr, func() {
		s.executeSchedule(scheduleID, scanType)
	})
	if err != nil {
		return fmt.Errorf("注册 cron 任务失败: %w", err)
	}

	s.entryMap[scheduleID] = entryID
	s.logger.Info("注册扫描计划",
		zap.Uint("id", sch.ID),
		zap.String("name", sch.Name),
		zap.String("cron", sch.CronExpr))
	return nil
}

// executeSchedule 执行扫描计划
func (s *ScanScheduler) executeSchedule(scheduleID uint, scanType string) {
	s.logger.Info("定时扫描触发", zap.Uint("schedule_id", scheduleID), zap.String("type", scanType))

	now := model.Now()
	s.db.Model(&model.ScanSchedule{}).Where("id = ?", scheduleID).
		Update("last_run_at", now)

	// 创建执行记录
	exec := model.ScanScheduleExecution{
		ScheduleID: scheduleID,
		ScanType:   scanType,
		Status:     "running",
		StartedAt:  now,
	}
	s.db.Create(&exec)

	var err error
	switch scanType {
	case "full_scan":
		err = s.scanner.ScanAll()
	case "incremental_scan":
		err = s.scanner.ScanIncremental()
	case "sync_only":
		err = s.scanner.SyncOnly()
	default:
		s.logger.Warn("未知的扫描类型", zap.String("type", scanType))
		finishedAt := model.Now()
		s.db.Model(&exec).Updates(map[string]any{
			"status":      "failed",
			"error_msg":   "未知的扫描类型: " + scanType,
			"finished_at": finishedAt,
		})
		return
	}

	// 更新执行记录
	finishedAt := model.Now()
	duration := int(time.Since(time.Time(now)).Seconds())
	updates := map[string]any{
		"finished_at": finishedAt,
		"duration":    duration,
	}
	if err != nil {
		updates["status"] = "failed"
		updates["error_msg"] = err.Error()
		s.logger.Error("定时扫描执行失败", zap.Uint("schedule_id", scheduleID), zap.Error(err))
	} else {
		updates["status"] = "success"
	}
	s.db.Model(&exec).Updates(updates)

	// 更新下次执行时间
	entry, ok := s.entryMap[scheduleID]
	if ok {
		nextRun := s.cron.Entry(entry).Next
		lt := model.ToLocalTime(nextRun)
		s.db.Model(&model.ScanSchedule{}).Where("id = ?", scheduleID).
			Update("next_run_at", lt)
	}
}
