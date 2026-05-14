package biz

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/service"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	taskDispatchInterval = 5 * time.Second
	// 分布式锁 key，同一时刻只有一个 Manager 实例执行调度
	dispatchLockKey = "mxsec:task:dispatch:lock"
	// 锁 TTL 略大于调度间隔，防止持锁实例宕机后锁不释放
	dispatchLockTTL = 8 * time.Second
	// FIM 周期策略检查间隔（避免每 5 秒都扫策略表）
	fimPolicyCheckInterval = 5 * time.Minute
	// FIM 事件超时升级检查间隔
	fimEscalationCheckInterval = 5 * time.Minute
	// 漏洞扫描周期（一天一次；也会在首次启动发现库为空时立刻跑）
	vulnScanInterval = 24 * time.Hour
	// 漏洞扫描检查间隔（避免每 5 秒都判断一次）
	vulnScanCheckInterval = 10 * time.Minute
	// 僵尸任务超时时间（running 状态超过此时长自动标记为 failed）
	zombieTaskTimeout = 2 * time.Hour
	// 僵尸任务检查间隔
	zombieTaskCheckInterval = 5 * time.Minute
)

// managerInstanceID 当前 Manager 实例的唯一标识（进程启动时生成一次）
var managerInstanceID = func() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", host, time.Now().UnixNano())
}()

// TaskScheduler 在 Manager 侧周期性调度任务下发
// 使用 Redis 分布式锁保证多 Manager 实例下只有一个执行调度
type TaskScheduler struct {
	db                     *gorm.DB
	taskService            *service.TaskService
	dispatcher             *sd.ACDispatcher
	redisClient            *redis.Client
	logger                 *zap.Logger
	lastFIMCheck           time.Time // 上次 FIM 策略扫描时间（用于节流）
	lastFIMEscalationCheck time.Time // 上次 FIM 事件超时升级检查时间
	lastVulnCheck          time.Time // 上次漏洞扫描判断时间（节流）
	lastVulnScanStart      time.Time // 上次实际触发漏洞扫描的时间
	lastZombieCheck        time.Time // 上次僵尸任务检查时间
}

// NewTaskScheduler 创建 TaskScheduler
// redisClient 可为 nil：降级为无锁模式（单 Manager 实例时安全）
func NewTaskScheduler(db *gorm.DB, dispatcher *sd.ACDispatcher, redisClient *redis.Client, logger *zap.Logger) *TaskScheduler {
	return &TaskScheduler{
		db:          db,
		taskService: service.NewTaskService(db, logger),
		dispatcher:  dispatcher,
		redisClient: redisClient,
		logger:      logger,
	}
}

// Start 启动调度循环，ctx 取消时退出（应在 goroutine 中调用）
func (s *TaskScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(taskDispatchInterval)
	defer ticker.Stop()

	s.logger.Info("Manager 任务调度器已启动",
		zap.Duration("interval", taskDispatchInterval),
		zap.Bool("redis_lock_enabled", s.redisClient != nil),
		zap.String("instance_id", managerInstanceID),
	)

	// 立即执行一次
	s.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Manager 任务调度器已停止")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce 尝试获取分布式锁并执行一轮调度
func (s *TaskScheduler) runOnce(ctx context.Context) {
	if !s.acquireLock(ctx) {
		return // 另一个 Manager 实例正在调度，本轮跳过
	}
	defer s.releaseLock(ctx)

	if err := s.taskService.DispatchPendingTasks(s.dispatcher); err != nil {
		s.logger.Error("分发检查任务失败", zap.Error(err))
	}
	if err := s.taskService.DispatchPendingFixTasks(s.dispatcher); err != nil {
		s.logger.Error("分发修复任务失败", zap.Error(err))
	}
	if err := s.taskService.DispatchPendingFIMTasks(s.dispatcher); err != nil {
		s.logger.Error("分发 FIM 任务失败", zap.Error(err))
	}
	if err := s.taskService.DispatchPendingAntivirusTasks(s.dispatcher); err != nil {
		s.logger.Error("分发病毒扫描任务失败", zap.Error(err))
	}

	// 分发已确认的漏洞修复任务
	remExecutor := NewRemediationExecutor(s.db, s.logger)
	if err := remExecutor.DispatchConfirmedTasks(s.dispatcher); err != nil {
		s.logger.Error("分发漏洞修复任务失败", zap.Error(err))
	}

	// FIM 周期策略检查（节流：默认 5 分钟扫一次策略表）
	if time.Since(s.lastFIMCheck) >= fimPolicyCheckInterval {
		s.scheduleFIMPeriodicTasks()
		s.lastFIMCheck = time.Now()
	}

	// FIM 事件超时升级检查（节流：默认 5 分钟检查一次）
	if time.Since(s.lastFIMEscalationCheck) >= fimEscalationCheckInterval {
		EscalatePendingFIMEvents(s.db, s.logger)
		s.lastFIMEscalationCheck = time.Now()
	}

	// 漏洞扫描周期判断（节流：默认 10 分钟判断一次）
	if time.Since(s.lastVulnCheck) >= vulnScanCheckInterval {
		s.maybeTriggerVulnScan()
		s.lastVulnCheck = time.Now()
	}

	// 僵尸任务超时检查（节流：默认 5 分钟检查一次）
	if time.Since(s.lastZombieCheck) >= zombieTaskCheckInterval {
		s.timeoutZombieTasks()
		s.lastZombieCheck = time.Now()
	}
}

// scheduleFIMPeriodicTasks 基于 fim_policies.check_interval_hours 自动创建 FIM 任务
// 规则：对于 enabled=true 且 check_interval_hours>0 的策略，若最近一次任务
// 的 created_at 超过 interval，则创建新的 pending 任务（由下一轮 runOnce 派发）
func (s *TaskScheduler) scheduleFIMPeriodicTasks() {
	if s.db == nil {
		return
	}

	var policies []model.FIMPolicy
	if err := s.db.Where("enabled = ? AND check_interval_hours > 0", true).
		Find(&policies).Error; err != nil {
		s.logger.Error("查询 FIM 策略失败", zap.Error(err))
		return
	}

	for i := range policies {
		p := &policies[i]

		// 查询该策略最近一次任务
		var latest model.FIMTask
		err := s.db.Where("policy_id = ?", p.PolicyID).
			Order("created_at DESC").
			First(&latest).Error

		needCreate := false
		if err != nil {
			// 该策略从未有任务 → 创建首个任务
			needCreate = true
		} else {
			// 若存在 pending/running 任务则跳过（避免堆积）
			if latest.Status == "pending" || latest.Status == "running" {
				continue
			}
			// 最近一次任务距今超过 check_interval_hours → 创建新任务
			interval := time.Duration(p.CheckIntervalHours) * time.Hour
			if time.Since(time.Time(latest.CreatedAt)) >= interval {
				needCreate = true
			}
		}

		if !needCreate {
			continue
		}

		targetType := p.TargetType
		if targetType == "" {
			targetType = "all"
		}

		task := &model.FIMTask{
			TaskID:       uuid.New().String(),
			PolicyID:     p.PolicyID,
			Status:       "pending",
			TargetType:   targetType,
			TargetConfig: p.TargetConfig,
			CreatedAt:    model.LocalTime(time.Now()),
		}

		if err := s.db.Create(task).Error; err != nil {
			s.logger.Error("创建周期 FIM 任务失败",
				zap.String("policy_id", p.PolicyID),
				zap.Error(err))
			continue
		}

		s.logger.Info("已创建周期 FIM 任务",
			zap.String("policy_id", p.PolicyID),
			zap.String("policy_name", p.Name),
			zap.String("task_id", task.TaskID),
			zap.Int("check_interval_hours", p.CheckIntervalHours))
	}
}

// timeoutZombieTasks 将超时的 running 任务标记为 failed
// 覆盖: ScanTask、FixTask、FIMTask、AntivirusScanTask
func (s *TaskScheduler) timeoutZombieTasks() {
	if s.db == nil {
		return
	}

	cutoff := time.Now().Add(-zombieTaskTimeout)
	now := model.LocalTime(time.Now())

	// 基线检查任务
	result := s.db.Model(&model.ScanTask{}).
		Where("status = ? AND updated_at < ?", model.TaskStatusRunning, cutoff).
		Updates(map[string]interface{}{
			"status":        model.TaskStatusFailed,
			"failed_reason": "任务超时（超过 2 小时未完成）",
			"completed_at":  &now,
		})
	if result.RowsAffected > 0 {
		s.logger.Warn("基线检查僵尸任务已超时",
			zap.Int64("count", result.RowsAffected))
	}

	// 修复任务
	result = s.db.Model(&model.FixTask{}).
		Where("status = ? AND updated_at < ?", model.FixTaskStatusRunning, cutoff).
		Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": &now,
		})
	if result.RowsAffected > 0 {
		s.logger.Warn("修复僵尸任务已超时",
			zap.Int64("count", result.RowsAffected))
	}

	// FIM 任务
	result = s.db.Model(&model.FIMTask{}).
		Where("status = ? AND updated_at < ?", "running", cutoff).
		Updates(map[string]interface{}{
			"status":       "failed",
			"completed_at": &now,
		})
	if result.RowsAffected > 0 {
		s.logger.Warn("FIM 僵尸任务已超时",
			zap.Int64("count", result.RowsAffected))
	}

	// 病毒扫描任务
	result = s.db.Model(&model.AntivirusScanTask{}).
		Where("status = ? AND updated_at < ?", "running", cutoff).
		Updates(map[string]interface{}{
			"status":      "failed",
			"finished_at": &now,
		})
	if result.RowsAffected > 0 {
		s.logger.Warn("病毒扫描僵尸任务已超时",
			zap.Int64("count", result.RowsAffected))
	}
}

// acquireLock 尝试获取 Redis 分布式锁
// Redis 不可用时降级为无锁模式（允许调度，极低概率重复）
func (s *TaskScheduler) acquireLock(ctx context.Context) bool {
	if s.redisClient == nil {
		return true
	}
	result, err := s.redisClient.SetArgs(ctx, dispatchLockKey, managerInstanceID,
		redis.SetArgs{Mode: "NX", TTL: dispatchLockTTL}).Result()
	if err != nil {
		s.logger.Warn("获取调度锁失败，降级为无锁执行", zap.Error(err))
		return true
	}
	return result == "OK"
}

// maybeTriggerVulnScan 根据周期或"首次启动库为空"策略触发一次漏洞扫描
// - 首次启动：若 vulnerabilities 表为空但 software 表有带 PURL 的记录，立即扫一次
// - 周期：距离上次扫描 >= vulnScanInterval 时扫一次
// 扫描本身异步执行，避免阻塞调度循环
func (s *TaskScheduler) maybeTriggerVulnScan() {
	if s.db == nil {
		return
	}

	shouldScan := false
	reason := ""

	// 周期触发
	if !s.lastVulnScanStart.IsZero() && time.Since(s.lastVulnScanStart) >= vulnScanInterval {
		shouldScan = true
		reason = "periodic"
	}

	// 首次启动触发：库为空且存在待扫描的 PURL
	if !shouldScan && s.lastVulnScanStart.IsZero() {
		var vulnCount int64
		s.db.Model(&model.Vulnerability{}).Count(&vulnCount)

		var swCount int64
		s.db.Model(&model.Software{}).Where("purl != '' AND purl IS NOT NULL").Count(&swCount)

		if vulnCount == 0 && swCount > 0 {
			shouldScan = true
			reason = "initial"
		} else if vulnCount == 0 && swCount == 0 {
			// 尚无软件包上报，稍后再试（不打标记）
			return
		} else {
			// 库非空说明之前已有人工触发过，按周期模式开始计时
			s.lastVulnScanStart = time.Now()
			return
		}
	}

	if !shouldScan {
		return
	}

	s.lastVulnScanStart = time.Now()
	s.logger.Info("触发周期漏洞扫描", zap.String("reason", reason))

	go func() {
		scanner := NewVulnScanner(s.db, s.logger)
		if err := scanner.ScanAll(); err != nil {
			s.logger.Error("周期漏洞扫描失败", zap.Error(err))
		}
	}()
}

// releaseLock 原子释放 Redis 分布式锁（只释放自己加的锁）
func (s *TaskScheduler) releaseLock(ctx context.Context) {
	if s.redisClient == nil {
		return
	}
	const script = `if redis.call("get",KEYS[1])==ARGV[1] then return redis.call("del",KEYS[1]) else return 0 end`
	if err := s.redisClient.Eval(ctx, script, []string{dispatchLockKey}, managerInstanceID).Err(); err != nil {
		s.logger.Warn("释放调度锁失败", zap.Error(err))
	}
}
