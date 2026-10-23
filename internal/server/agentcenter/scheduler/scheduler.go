// Package scheduler 提供任务调度器
package scheduler

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/service"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/remediation"
)

// taskDispatchInterval 是任务调度器的轮询间隔
const taskDispatchInterval = 5 * time.Second

// StartTaskScheduler 启动任务调度器（定期分发待执行任务）
func StartTaskScheduler(taskService *service.TaskService, transferService *transfer.Service, db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(taskDispatchInterval)
	defer ticker.Stop()

	logger.Info("任务调度器已启动", zap.Duration("interval", taskDispatchInterval))

	remExecutor := remediation.NewRemediationExecutor(db, logger)

	// 立即执行一次
	dispatchAllPendingTasks(taskService, transferService, remExecutor, logger)

	// 定时执行
	for range ticker.C {
		dispatchAllPendingTasks(taskService, transferService, remExecutor, logger)
	}
}

// dispatchAllPendingTasks 分发所有待执行任务（检查任务、修复任务、FIM 任务、漏洞修复任务）
func dispatchAllPendingTasks(taskService *service.TaskService, transferService *transfer.Service, remExecutor *remediation.RemediationExecutor, logger *zap.Logger) {
	// 分发基线检查任务
	if err := taskService.DispatchPendingTasks(transferService); err != nil {
		logger.Error("分发检查任务失败", zap.Error(err))
	}

	// 分发基线修复任务
	if err := taskService.DispatchPendingFixTasks(transferService); err != nil {
		logger.Error("分发修复任务失败", zap.Error(err))
	}

	// 分发 FIM 检查任务
	if err := taskService.DispatchPendingFIMTasks(transferService); err != nil {
		logger.Error("分发 FIM 任务失败", zap.Error(err))
	}

	// 分发漏洞修复任务（用户确认后）
	if err := remExecutor.DispatchConfirmedTasks(transferService); err != nil {
		logger.Error("分发漏洞修复任务失败", zap.Error(err))
	}
}
