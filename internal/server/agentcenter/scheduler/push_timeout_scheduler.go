// Package scheduler 提供任务调度器
package scheduler

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// pushTimeoutMinutes 插件推送超时阈值（分钟）
const pushTimeoutMinutes = 10

// StartPushTimeoutScheduler 启动插件推送超时调度器
// 每 60 秒扫描一次 pushing 状态的推送记录，超时则根据主机状态汇总结果
func StartPushTimeoutScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	logger.Info("插件推送超时调度器已启动",
		zap.Duration("check_interval", 60*time.Second),
		zap.Int("timeout_minutes", pushTimeoutMinutes))

	// 启动时立即检查一次
	checkPushTimeout(db, logger)

	for range ticker.C {
		checkPushTimeout(db, logger)
	}
}

// checkPushTimeout 检查超时的插件推送记录
func checkPushTimeout(db *gorm.DB, logger *zap.Logger) {
	deadline := time.Now().Add(-time.Duration(pushTimeoutMinutes) * time.Minute)

	var records []model.ComponentPushRecord
	if err := db.Where("status = ? AND created_at < ?", model.ComponentPushStatusPushing, deadline).
		Find(&records).Error; err != nil {
		logger.Error("查询超时推送记录失败", zap.Error(err))
		return
	}

	if len(records) == 0 {
		return
	}

	logger.Info("检测到超时的推送记录", zap.Int("count", len(records)))

	for _, record := range records {
		handlePushRecordTimeout(db, logger, &record)
	}
}

// handlePushRecordTimeout 处理单条超时的推送记录
func handlePushRecordTimeout(db *gorm.DB, logger *zap.Logger, record *model.ComponentPushRecord) {
	// 查询关联的主机推送记录
	var hosts []model.ComponentPushHost
	if err := db.Where("record_id = ?", record.ID).Find(&hosts).Error; err != nil {
		logger.Error("查询推送主机记录失败",
			zap.Uint("record_id", record.ID),
			zap.Error(err))
		return
	}

	// 统计各状态数量
	var successCount, failedCount, pendingCount int
	var failedHostIDs []string

	for _, host := range hosts {
		switch host.Status {
		case model.ComponentPushHostStatusSuccess:
			successCount++
		case model.ComponentPushHostStatusFailed:
			failedCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
		default:
			pendingCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
		}
	}

	// 将仍为 pending 的主机标记为 failed
	if pendingCount > 0 {
		db.Model(&model.ComponentPushHost{}).
			Where("record_id = ? AND status = ?", record.ID, model.ComponentPushHostStatusPending).
			Updates(map[string]interface{}{
				"status":  model.ComponentPushHostStatusFailed,
				"message": "推送超时",
			})
	}

	// 更新推送记录
	now := model.ToLocalTime(time.Now())
	status := model.ComponentPushStatusFailed
	if successCount > 0 && failedCount == 0 && pendingCount == 0 {
		status = model.ComponentPushStatusSuccess
	}

	db.Model(record).Updates(map[string]interface{}{
		"status":        status,
		"success_count": successCount,
		"failed_count":  failedCount + pendingCount,
		"failed_hosts":  model.StringArray(failedHostIDs),
		"completed_at":  &now,
	})

	logger.Warn("推送记录超时已处理",
		zap.Uint("record_id", record.ID),
		zap.String("component", record.ComponentName),
		zap.String("version", record.Version),
		zap.String("final_status", string(status)),
		zap.Int("success", successCount),
		zap.Int("failed", failedCount),
		zap.Int("timeout", pendingCount))
}
