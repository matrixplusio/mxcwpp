package scheduler

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// BDE 维护参数（P3）。
const (
	baselineMaintInterval      = 12 * time.Hour // 维护周期
	behaviorAlertRetentionDays = 30             // behavior_alerts 保留天数(瞬态异常快照,过期删)
)

// StartBaselineMaintenanceScheduler 启动 BDE 维护调度器（P3）。
//
// 周期清理两类垃圾：
//   - stale 基线：host_baseline_states 中 host_id 已不在 hosts 表的残留行
//     (agent host_id 重生留下的旧基线，prod 实测 256 行 > 232 主机)。
//   - 过期 behavior_alerts：超保留期的行(瞬态异常快照，长期分析走 storyline_events)。
func StartBaselineMaintenanceScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(baselineMaintInterval)
	defer ticker.Stop()

	logger.Info("BDE 维护调度器已启动", zap.Duration("interval", baselineMaintInterval))

	processBaselineMaintenance(db, logger)
	for range ticker.C {
		processBaselineMaintenance(db, logger)
	}
}

// processBaselineMaintenance 执行一轮 GC。
func processBaselineMaintenance(db *gorm.DB, logger *zap.Logger) {
	// 1. stale 基线 GC：删除 host 已不存在的基线行。
	staleRes := db.Exec(
		"DELETE FROM host_baseline_states WHERE host_id NOT IN (SELECT host_id FROM hosts)")
	if staleRes.Error != nil {
		logger.Warn("stale 基线 GC 失败", zap.Error(staleRes.Error))
	} else if staleRes.RowsAffected > 0 {
		logger.Info("已清理 stale 基线", zap.Int64("deleted", staleRes.RowsAffected))
	}

	// 2. 过期 behavior_alerts 删除。
	cutoff := model.ToLocalTime(time.Now().Add(-behaviorAlertRetentionDays * 24 * time.Hour))
	baRes := db.Where("created_at < ?", cutoff).Delete(&model.BehaviorAlert{})
	if baRes.Error != nil {
		logger.Warn("过期 behavior_alerts 清理失败", zap.Error(baRes.Error))
	} else if baRes.RowsAffected > 0 {
		logger.Info("已清理过期 behavior_alerts",
			zap.Int64("deleted", baRes.RowsAffected),
			zap.Int("retention_days", behaviorAlertRetentionDays))
	}
}
