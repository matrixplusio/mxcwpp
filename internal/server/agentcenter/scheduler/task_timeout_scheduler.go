// Package scheduler 提供任务调度器
package scheduler

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
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

// pendingTaskMaxAge pending 任务的最大留存时长。
// 超过此时长仍 pending（通常因无在线主机匹配）会被统一标 timeout，
// 避免僵尸 task 永驻 + scheduler 反复扫描日志噪声。
const pendingTaskMaxAge = 24 * time.Hour

// checkTimeoutTasks 检查超时任务
func checkTimeoutTasks(db *gorm.DB, logger *zap.Logger) {
	// 检查 pending 状态的检查任务超时
	checkPendingTasksTimeout(db, logger)

	// 检查 running 状态的检查任务超时
	checkRunningTasksTimeout(db, logger)

	// 检查修复任务超时
	checkFixTasksTimeout(db, logger)

	// 检查 FIM / 病毒扫描 / 漏洞修复任务的 pending 超时
	checkFIMTasksPendingTimeout(db, logger)
	checkAntivirusTasksPendingTimeout(db, logger)
	checkRemediationTasksPendingTimeout(db, logger)
}

// checkFIMTasksPendingTimeout 标记超过 pendingTaskMaxAge 仍 pending 的 FIM 任务为 timeout。
func checkFIMTasksPendingTimeout(db *gorm.DB, logger *zap.Logger) {
	deadline := time.Now().Add(-pendingTaskMaxAge)
	result := db.Model(&model.FIMTask{}).
		Where("status = ? AND created_at < ?", "pending", deadline).
		Update("status", "timeout")
	if result.Error != nil {
		logger.Error("FIM pending 任务超时标记失败", zap.Error(result.Error))
		return
	}
	if result.RowsAffected > 0 {
		logger.Info("FIM pending 任务超时标记完成",
			zap.Int64("affected", result.RowsAffected),
			zap.Duration("max_age", pendingTaskMaxAge),
		)
	}
}

// checkAntivirusTasksPendingTimeout 标记超过 pendingTaskMaxAge 仍 pending 的病毒扫描任务为 failed。
// AntivirusScanTask status enum 无 timeout，复用 failed。
func checkAntivirusTasksPendingTimeout(db *gorm.DB, logger *zap.Logger) {
	deadline := time.Now().Add(-pendingTaskMaxAge)
	result := db.Model(&model.AntivirusScanTask{}).
		Where("status = ? AND created_at < ?", "pending", deadline).
		Update("status", "failed")
	if result.Error != nil {
		logger.Error("病毒扫描 pending 任务超时标记失败", zap.Error(result.Error))
		return
	}
	if result.RowsAffected > 0 {
		logger.Info("病毒扫描 pending 任务超时标记完成",
			zap.Int64("affected", result.RowsAffected),
			zap.Duration("max_age", pendingTaskMaxAge),
		)
	}
}

// checkRemediationTasksPendingTimeout 标记超过 pendingTaskMaxAge 仍 pending 的漏洞修复任务为 failed。
func checkRemediationTasksPendingTimeout(db *gorm.DB, logger *zap.Logger) {
	deadline := time.Now().Add(-pendingTaskMaxAge)
	result := db.Model(&model.RemediationTask{}).
		Where("status = ? AND created_at < ?", "pending", deadline).
		Update("status", "failed")
	if result.Error != nil {
		logger.Error("漏洞修复 pending 任务超时标记失败", zap.Error(result.Error))
		return
	}
	if result.RowsAffected > 0 {
		logger.Info("漏洞修复 pending 任务超时标记完成",
			zap.Int64("affected", result.RowsAffected),
			zap.Duration("max_age", pendingTaskMaxAge),
		)
	}
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

// handleRunningTaskTimeout 处理 running 任务超时：
//   - 全部主机已返回结果 → completed
//   - 仍有未完成主机且重试未耗尽 → 回 pending，由调度器重排未完成主机（retry）
//   - 重试耗尽：有部分结果 → partial（接受部分结果）；无任何结果 → failed
//
// 大批量并发扫描下，部分主机会非确定性地不返回结果。整任务直接判失败会丢弃已完成主机
// 的有效结果且无自愈；改为自动重排未完成主机 + 接受部分结果，使重扫可最终收敛。
func handleRunningTaskTimeout(db *gorm.DB, logger *zap.Logger, task *model.ScanTask) {
	var resultCount int64
	db.Model(&model.ScanResult{}).Where("task_id = ?", task.TaskID).Count(&resultCount)

	completedAt := model.Now()

	// 全部主机已返回结果 → 完成。
	// CAS：仅当任务仍为 running 时更新，避免与 consumer 的 WriteTaskCompletion 并发标 completed
	// 互相覆盖（consumer 在最后一台完成时也会标 completed）。
	if task.DispatchedHostCount > 0 && task.CompletedHostCount >= task.DispatchedHostCount {
		res := db.Model(&model.ScanTask{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.TaskStatusRunning).
			Updates(map[string]interface{}{
				"status":       model.TaskStatusCompleted,
				"completed_at": &completedAt,
			})
		if res.RowsAffected > 0 {
			logger.Info("running 任务超时，但所有主机都返回了结果，标记为完成",
				zap.String("task_id", task.TaskID),
				zap.Int("dispatched_host_count", task.DispatchedHostCount),
				zap.Int("completed_host_count", task.CompletedHostCount),
			)
			metrics.IncBaselineTaskOutcome(metrics.BaselineOutcomeCompleted)
		}
		return
	}

	// 仍有未完成主机，且重试未耗尽 → 回 pending，由 DispatchPendingTasks 重排未完成主机。
	// CAS：仅当仍为 running 且确有未完成主机（completed < dispatched）才转 pending。
	// 否则（consumer 已并发标 completed）不覆盖、不重排，防止把已完成任务打回 pending
	// 后因无可重排主机而卡死、被 pending-timeout 误判失败。
	if task.RetryCount < task.MaxRetries {
		now := model.Now()
		res := db.Model(&model.ScanTask{}).
			Where("task_id = ? AND status = ? AND completed_host_count < dispatched_host_count",
				task.TaskID, model.TaskStatusRunning).
			Updates(map[string]interface{}{
				"status":        model.TaskStatusPending,
				"retry_count":   task.RetryCount + 1,
				"executed_at":   &now, // 重置超时窗口，重排后重新计时
				"failed_reason": "",
			})
		if res.RowsAffected > 0 {
			logger.Warn("running 任务超时，重排未完成主机",
				zap.String("task_id", task.TaskID),
				zap.Int("retry_count", task.RetryCount+1),
				zap.Int("max_retries", task.MaxRetries),
				zap.Int("dispatched_host_count", task.DispatchedHostCount),
				zap.Int("completed_host_count", task.CompletedHostCount),
			)
			metrics.IncBaselineTaskOutcome(metrics.BaselineOutcomeRetried)
		}
		return
	}

	// 重试耗尽 → 标记未完成主机为 timeout，并据是否有结果定终态（终态同样 CAS 守卫 running）
	db.Model(&model.TaskHostStatus{}).
		Where("task_id = ? AND status = ?", task.TaskID, model.TaskHostStatusDispatched).
		Updates(map[string]interface{}{
			"status":        model.TaskHostStatusTimeout,
			"error_message": "任务执行超时：主机未返回结果",
		})

	if resultCount == 0 {
		res := db.Model(&model.ScanTask{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.TaskStatusRunning).
			Updates(map[string]interface{}{
				"status":        model.TaskStatusFailed,
				"failed_reason": "任务执行超时：没有收到任何主机的结果",
				"completed_at":  &completedAt,
			})
		if res.RowsAffected > 0 {
			logger.Warn("running 任务超时，重试耗尽且无任何结果，标记为失败",
				zap.String("task_id", task.TaskID),
				zap.Int("dispatched_host_count", task.DispatchedHostCount),
			)
			metrics.IncBaselineTaskOutcome(metrics.BaselineOutcomeFailed)
		}
		return
	}

	failedHostCount := task.DispatchedHostCount - task.CompletedHostCount
	res := db.Model(&model.ScanTask{}).
		Where("task_id = ? AND status = ?", task.TaskID, model.TaskStatusRunning).
		Updates(map[string]interface{}{
			"status":        model.TaskStatusPartial,
			"failed_reason": fmt.Sprintf("任务执行超时：%d 台主机未返回结果（已接受部分结果）", failedHostCount),
			"completed_at":  &completedAt,
		})
	if res.RowsAffected > 0 {
		logger.Warn("running 任务超时，重试耗尽，部分主机未返回结果，标记为部分完成",
			zap.String("task_id", task.TaskID),
			zap.Int("dispatched_host_count", task.DispatchedHostCount),
			zap.Int("completed_host_count", task.CompletedHostCount),
			zap.Int64("result_count", resultCount),
		)
		metrics.IncBaselineTaskOutcome(metrics.BaselineOutcomePartial)
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
