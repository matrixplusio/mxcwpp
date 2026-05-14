// Package scheduler 提供任务调度器
package scheduler

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// StartTaskTimeoutScheduler 启动任务超时调度器
// 每分钟检查一次 pending 和 running 状态的任务是否超时
func StartTaskTimeoutScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(1 * time.Minute) // 每分钟检查一次
	defer ticker.Stop()

	logger.Info("任务超时调度器已启动", zap.Duration("check_interval", 1*time.Minute))

	// 立即执行一次检查
	checkTimeoutTasks(db, logger)

	// 定时执行
	for range ticker.C {
		checkTimeoutTasks(db, logger)
	}
}

// checkTimeoutTasks 检查超时任务
func checkTimeoutTasks(db *gorm.DB, logger *zap.Logger) {
	// 检查 pending 状态的检查任务超时
	checkPendingTasksTimeout(db, logger)

	// 检查 running 状态的检查任务超时
	checkRunningTasksTimeout(db, logger)

	// 检查修复任务超时
	checkFixTasksTimeout(db, logger)
}

// checkPendingTasksTimeout 检查 pending 状态的任务是否超时
// 如果任务在 pending 状态超时（没有匹配到在线主机），标记为 failed
func checkPendingTasksTimeout(db *gorm.DB, logger *zap.Logger) {
	var tasks []model.ScanTask
	if err := db.Where("status = ?", model.TaskStatusPending).Find(&tasks).Error; err != nil {
		logger.Error("查询 pending 任务失败", zap.Error(err))
		return
	}

	if len(tasks) == 0 {
		return
	}

	now := time.Now()
	for _, task := range tasks {
		// 计算超时时间
		timeoutMinutes := task.TimeoutMinutes
		if timeoutMinutes <= 0 {
			timeoutMinutes = 10 // 默认 10 分钟
		}

		// 从 executed_at 开始计算超时（用户点击执行的时间）
		if task.ExecutedAt == nil {
			continue
		}

		executedAt := task.ExecutedAt.Time()
		deadline := executedAt.Add(time.Duration(timeoutMinutes) * time.Minute)

		if now.After(deadline) {
			// 超时，标记为失败
			logger.Warn("pending 任务超时，标记为失败",
				zap.String("task_id", task.TaskID),
				zap.Time("executed_at", executedAt),
				zap.Int("timeout_minutes", timeoutMinutes),
			)

			db.Model(&task).Updates(map[string]interface{}{
				"status":        model.TaskStatusFailed,
				"failed_reason": "等待主机超时：没有匹配到在线主机",
				"completed_at":  model.Now(),
			})
		}
	}
}

// checkRunningTasksTimeout 检查 running 状态的任务是否超时
// 如果任务在 running 状态超时（部分/全部主机没有返回结果），根据结果决定最终状态
func checkRunningTasksTimeout(db *gorm.DB, logger *zap.Logger) {
	var tasks []model.ScanTask
	if err := db.Where("status = ?", model.TaskStatusRunning).Find(&tasks).Error; err != nil {
		logger.Error("查询 running 任务失败", zap.Error(err))
		return
	}

	if len(tasks) == 0 {
		return
	}

	now := time.Now()
	for _, task := range tasks {
		// 计算超时时间
		timeoutMinutes := task.TimeoutMinutes
		if timeoutMinutes <= 0 {
			timeoutMinutes = 10 // 默认 10 分钟
		}

		// 从 executed_at 开始计算超时
		if task.ExecutedAt == nil {
			continue
		}

		executedAt := task.ExecutedAt.Time()
		deadline := executedAt.Add(time.Duration(timeoutMinutes) * time.Minute)

		if now.After(deadline) {
			// 超时，根据是否有结果决定状态
			handleRunningTaskTimeout(db, logger, &task)
		}
	}
}

// handleRunningTaskTimeout 处理 running 任务超时
func handleRunningTaskTimeout(db *gorm.DB, logger *zap.Logger, task *model.ScanTask) {
	// 查询该任务的结果数量
	var resultCount int64
	db.Model(&model.ScanResult{}).Where("task_id = ?", task.TaskID).Count(&resultCount)

	completedAt := model.Now()

	if resultCount == 0 {
		// 完全没有结果，标记为失败
		logger.Warn("running 任务超时，没有任何结果，标记为失败",
			zap.String("task_id", task.TaskID),
			zap.Int("dispatched_host_count", task.DispatchedHostCount),
		)

		// 标记所有未完成的主机为超时
		db.Model(&model.TaskHostStatus{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.TaskHostStatusDispatched).
			Updates(map[string]interface{}{
				"status":        model.TaskHostStatusTimeout,
				"error_message": "任务执行超时：主机未返回结果",
			})

		db.Model(task).Updates(map[string]interface{}{
			"status":        model.TaskStatusFailed,
			"failed_reason": "任务执行超时：没有收到任何主机的结果",
			"completed_at":  &completedAt,
		})
	} else if task.DispatchedHostCount > 0 && task.CompletedHostCount < task.DispatchedHostCount {
		// 有部分结果，但不是所有主机都返回了，标记为失败
		logger.Warn("running 任务超时，部分主机未返回结果，标记为失败",
			zap.String("task_id", task.TaskID),
			zap.Int("dispatched_host_count", task.DispatchedHostCount),
			zap.Int("completed_host_count", task.CompletedHostCount),
			zap.Int64("result_count", resultCount),
		)

		// 标记所有未完成的主机为超时
		db.Model(&model.TaskHostStatus{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.TaskHostStatusDispatched).
			Updates(map[string]interface{}{
				"status":        model.TaskHostStatusTimeout,
				"error_message": "任务执行超时：主机未返回结果",
			})

		failedHostCount := task.DispatchedHostCount - task.CompletedHostCount
		db.Model(task).Updates(map[string]interface{}{
			"status":        model.TaskStatusFailed,
			"failed_reason": fmt.Sprintf("任务执行超时：%d 台主机未返回结果", failedHostCount),
			"completed_at":  &completedAt,
		})
	} else {
		// 所有主机都返回了结果，标记为完成
		logger.Info("running 任务超时，但所有主机都返回了结果，标记为完成",
			zap.String("task_id", task.TaskID),
			zap.Int("dispatched_host_count", task.DispatchedHostCount),
			zap.Int("completed_host_count", task.CompletedHostCount),
		)

		db.Model(task).Updates(map[string]interface{}{
			"status":       model.TaskStatusCompleted,
			"completed_at": &completedAt,
		})
	}
}

// fixTaskTimeoutMinutes 修复任务超时时间（分钟）
const fixTaskTimeoutMinutes = 15

// checkFixTasksTimeout 检查修复任务超时
// 如果修复任务在 running 状态超过 15 分钟，根据已有结果决定最终状态
func checkFixTasksTimeout(db *gorm.DB, logger *zap.Logger) {
	var tasks []model.FixTask
	if err := db.Where("status IN ?", []string{
		string(model.FixTaskStatusPending),
		string(model.FixTaskStatusRunning),
	}).Find(&tasks).Error; err != nil {
		logger.Error("查询修复任务失败", zap.Error(err))
		return
	}

	if len(tasks) == 0 {
		return
	}

	now := time.Now()
	deadline := now.Add(-time.Duration(fixTaskTimeoutMinutes) * time.Minute)

	for _, task := range tasks {
		if task.CreatedAt.Time().After(deadline) {
			continue // 未超时
		}

		completedAt := model.Now()

		if task.SuccessCount+task.FailedCount > 0 {
			// 有结果，标记为完成
			logger.Warn("修复任务超时，已有部分结果，标记为完成",
				zap.String("task_id", task.TaskID),
				zap.Int("success_count", task.SuccessCount),
				zap.Int("failed_count", task.FailedCount),
			)
			db.Model(&task).Updates(map[string]interface{}{
				"status":       model.FixTaskStatusCompleted,
				"completed_at": &completedAt,
				"progress":     100,
			})
		} else {
			// 无结果，标记为失败
			logger.Warn("修复任务超时，无任何结果，标记为失败",
				zap.String("task_id", task.TaskID),
			)
			db.Model(&task).Updates(map[string]interface{}{
				"status":       model.FixTaskStatusFailed,
				"completed_at": &completedAt,
			})
		}

		// 标记超时主机
		db.Model(&model.FixTaskHostStatus{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.FixTaskHostStatusDispatched).
			Updates(map[string]interface{}{
				"status":        model.FixTaskHostStatusTimeout,
				"completed_at":  &completedAt,
				"error_message": "修复任务执行超时",
			})
	}
}
